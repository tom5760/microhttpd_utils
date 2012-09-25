/*
 * Copyright (c) 2012 Tom Wambold <tom5760@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file microhttpd_pubsub.h
 * Simple publish/subscribe mechanism using long-polling.
 *
 * Uses COMET or HTML5 Server Sent Event-style long-lived HTTP connections.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>

#include <uthash.h>
#include <utlist.h>

#include <microhttpd.h>

#include "microhttpd_pubsub.h"

static const size_t PUBSUB_BLOCK_SIZE = 80;

/** A published message. */
struct message {
    char *data;
    size_t length;

    enum MHD_ResponseMemoryMode respmem;

    unsigned int refcount;
};

/** An item in a subscription's message queue. */
struct queue_item {
    struct message *message;

    size_t num_read;

    /** Items kept in a doubly-linked list. */
    struct queue_item *prev;
    struct queue_item *next;
};

/** A particular client subscription on a channel. */
struct subscription {
    MHDU_PubSubCallback callback;
    void *cls;

    /** The channel this subscription is on. */
    struct channel *channel;

    /** The items in this subscription's message queue. */
    struct queue_item *queue;

    /** Lock protecting access to queue. */
    pthread_mutex_t lock;

    /** Condition variable to notify of new items in the queue. */
    pthread_cond_t cond;

    /** Items kept in a doubly-linked list. */
    struct subscription *prev;
    struct subscription *next;
};

/** Holds all the subscribers to a particular channel. */
struct channel {
    /** Channel name */
    char *name;

    /** The pubsub instance managing this channel. */
    struct MHDU_PubSub *pubsub;

    /** The subscriptions on this channel. */
    struct subscription *subscriptions;

    /** Lock protecting access to subscriptions. */
    pthread_mutex_t lock;

    /** Set when this channel is closed. */
    sig_atomic_t closed;

    /** Items stored in a hash table. */
    UT_hash_handle hh;
};

struct MHDU_PubSub {
    /** All active channels. */
    struct channel *channels;

    /** Lock protecting access to channels */
    pthread_mutex_t lock;
};

static ssize_t pubsub_callback(void *cls, uint64_t pos, char *buf, size_t max);
static void pubsub_free_callback(void *cls);

static struct channel* create_channel(struct MHDU_PubSub *pubsub,
        const char *name);
static void destroy_channel(struct channel *channel);
static struct channel* find_channel(struct MHDU_PubSub *pubsub,
        const char *name);
static unsigned int num_subscriptions(struct channel *channel);

static struct subscription* create_subscription(struct channel *channel,
        MHDU_PubSubCallback callback, void *cls);
static void destroy_subscription(struct subscription *subscription);

static struct queue_item* create_queue_item(struct message *message);
static void destroy_queue_item(struct queue_item *item);

static struct message* create_message(char *data, size_t length,
        enum MHD_ResponseMemoryMode respmem);
static void destroy_message(struct message *message);

static void ref_message(struct message *message);
static void unref_message(struct message *message);

struct MHDU_PubSub* MHDU_create_pubsub(void) {
    struct MHDU_PubSub *pubsub = calloc(1, sizeof(*pubsub));
    if (pubsub == NULL) {
        MHDU_ERR("Failed to allocate pubsub.");
        return NULL;
    }

    pubsub->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;

    return pubsub;
}

void MHDU_destroy_pubsub(struct MHDU_PubSub *pubsub) {
    pthread_mutex_lock(&pubsub->lock);

    struct channel *channel, *channel_tmp;
    HASH_ITER(hh, pubsub->channels, channel, channel_tmp) {
        HASH_DEL(pubsub->channels, channel);
        channel->closed = 1;

        pthread_mutex_lock(&channel->lock);
        struct subscription *sub, *sub_tmp;
        DL_FOREACH_SAFE(channel->subscriptions, sub, sub_tmp) {
            pthread_cond_broadcast(&sub->cond);
        }
        pthread_mutex_unlock(&channel->lock);
    }

    pthread_mutex_unlock(&pubsub->lock);
    free(pubsub);
}

struct MHD_Response* MHDU_create_response_from_subscription(
        struct MHDU_PubSub *pubsub, struct MHDU_Connection *mhdu_con,
        const char *chan_name, int *code, MHDU_PubSubCallback cb, void *cls) {

    pthread_mutex_lock(&pubsub->lock);
    struct channel *channel = find_channel(pubsub, chan_name);
    if (channel != NULL && channel->closed) {
        MHDU_ERR("Channel is closing.");
        return NULL;
    }
    if (channel == NULL) {
        channel = create_channel(pubsub, chan_name);
    }
    pthread_mutex_unlock(&pubsub->lock);
    if (channel == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&channel->lock);
    struct subscription *subscription = create_subscription(channel, cb, cls);
    if (subscription == NULL) {
        if (num_subscriptions(channel) == 0) {
            pthread_mutex_lock(&pubsub->lock);
            destroy_channel(channel);
            pthread_mutex_unlock(&pubsub->lock);
        }
        pthread_mutex_unlock(&channel->lock);
        return NULL;
    }
    DL_APPEND(channel->subscriptions, subscription);
    pthread_mutex_unlock(&channel->lock);

    *code = MHD_HTTP_OK;
    return MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
            PUBSUB_BLOCK_SIZE, pubsub_callback, subscription,
            pubsub_free_callback);
}

int MHDU_publish_data(struct MHDU_PubSub *pubsub, const char *name,
        const char *data, size_t length, enum MHD_ResponseMemoryMode respmem) {
    pthread_mutex_lock(&pubsub->lock);
    struct channel *channel = find_channel(pubsub, name);
    pthread_mutex_unlock(&pubsub->lock);
    if (channel == NULL) {
        MHDU_LOG("No subscriptions for channel %s", name);
        return MHD_YES;
    }

    struct message *message = create_message((char*)data, length, respmem);
    if (message == NULL) {
        MHDU_LOG("Failed to create message.");
        return MHD_NO;
    }

    pthread_mutex_lock(&channel->lock);
    struct subscription *subscription;
    DL_FOREACH(channel->subscriptions, subscription) {
        struct queue_item *item = create_queue_item(message);
        if (item == NULL) {
            MHDU_LOG("Failed to create queue item.");
            continue;
        }
        pthread_mutex_lock(&subscription->lock);
        DL_APPEND(subscription->queue, item);
        pthread_cond_broadcast(&subscription->cond);
        pthread_mutex_unlock(&subscription->lock);
    }
    pthread_mutex_unlock(&channel->lock);

    return MHD_YES;
}

static ssize_t pubsub_callback(void *cls, uint64_t pos, char *buf,
        size_t max) {
    struct subscription *subscription = (struct subscription*)cls;

    if (subscription->channel->closed) {
        return MHD_CONTENT_READER_END_OF_STREAM;
    }

    pthread_mutex_lock(&subscription->lock);
    if (subscription->queue == NULL) {
        pthread_cond_wait(&subscription->cond, &subscription->lock);

        /* Nobody removes items from the queue except for this function, so its
         * safe to look at the first item without a lock. */
        pthread_mutex_unlock(&subscription->lock);

        if (subscription->channel->closed) {
            return MHD_CONTENT_READER_END_OF_STREAM;
        }
    }

    struct queue_item *item = subscription->queue;
    struct message *message = item->message;

    size_t rv = subscription->callback(subscription->cls,
            subscription->channel->name, message->data, message->length,
            item->num_read, buf, max);
    item->num_read += rv;

    if (item->num_read == message->length) {
        pthread_mutex_lock(&subscription->lock);
        /* Pop the top element off the queue. */
        DL_DELETE(subscription->queue, item);
        pthread_mutex_unlock(&subscription->lock);

        pthread_mutex_lock(&subscription->channel->lock);
        destroy_queue_item(item);
        pthread_mutex_unlock(&subscription->channel->lock);
    }

    return rv;
}

static void pubsub_free_callback(void *cls) {
    struct subscription *subscription = (struct subscription*)cls;
    struct channel *channel = subscription->channel;

    pthread_mutex_lock(&channel->lock);
    DL_DELETE(channel->subscriptions, subscription);
    destroy_subscription((struct subscription*)cls);

    if (num_subscriptions(channel) == 0) {
        pthread_mutex_unlock(&channel->lock);
        destroy_channel(channel);
    } else {
        pthread_mutex_unlock(&channel->lock);
    }
}

static struct channel* create_channel(struct MHDU_PubSub *pubsub,
        const char *name) {
    struct channel *channel = calloc(1, sizeof(*channel));
    if (channel == NULL) {
        MHDU_ERR("Failed to allocate channel.");
        return NULL;
    }

    channel->name = strdup(name);
    if (channel->name == NULL) {
        MHDU_ERR("Failed to duplicate channel name.");
        goto error;
    }

    channel->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;

    HASH_ADD_KEYPTR(hh, pubsub->channels, channel->name,
            strlen(channel->name), channel);
    channel->pubsub = pubsub;

    return channel;

error:
    destroy_channel(channel);
    return NULL;
}

static void destroy_channel(struct channel *channel) {
    pthread_mutex_destroy(&channel->lock);
    free(channel->name);
    free(channel);
}

static struct channel *find_channel(struct MHDU_PubSub *pubsub,
        const char *name) {
    struct channel *channel;
    HASH_FIND_STR(pubsub->channels, name, channel);
    return channel;
}

static unsigned int num_subscriptions(struct channel *channel) {
    int num = 0;
    struct subscription *subscription;
    DL_FOREACH(channel->subscriptions, subscription) {
        num++;
    }
    return num;
}

static struct subscription* create_subscription(struct channel *channel,
        MHDU_PubSubCallback callback, void *cls) {
    struct subscription *subscription = calloc(1, sizeof(*subscription));
    if (subscription == NULL) {
        MHDU_ERR("Failed to allocate subscription.");
        return NULL;
    }

    subscription->channel = channel;
    subscription->callback = callback;
    subscription->cls = cls;

    subscription->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    subscription->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

    return subscription;
}

static void destroy_subscription(struct subscription *subscription) {
    pthread_mutex_lock(&subscription->lock);
    struct queue_item *item, *tmp;
    DL_FOREACH_SAFE(subscription->queue, item, tmp) {
        DL_DELETE(subscription->queue, item);
        destroy_queue_item(item);
    }
    pthread_mutex_unlock(&subscription->lock);

    pthread_mutex_destroy(&subscription->lock);
    pthread_cond_destroy(&subscription->cond);
    free(subscription);
}

static struct queue_item* create_queue_item(struct message *message) {
    struct queue_item* item = calloc(1, sizeof(*item));
    if (item == NULL) {
        MHDU_ERR("Failed to allocate queue item.");
        return NULL;
    }

    item->num_read = 0;
    item->message = message;
    ref_message(message);

    return item;
}

static void destroy_queue_item(struct queue_item *item) {
    unref_message(item->message);
    free(item);
}

static struct message* create_message(char *data, size_t length,
        enum MHD_ResponseMemoryMode respmem) {
    struct message *message = calloc(1, sizeof(*message));
    if (message == NULL) {
        MHDU_ERR("Failed allocating pubsub message.");
        return NULL;
    }

    message->refcount = 0;
    message->length = length;
    message->respmem = respmem;

    switch (respmem) {
        case MHD_RESPMEM_MUST_COPY:
            message->data = malloc(length);
            if (message->data == NULL) {
                MHDU_ERR("Failed to copy pubsub message data.");
                goto error;
            }
            memcpy(message->data, data, length);
            break;
        case MHD_RESPMEM_MUST_FREE:
        case MHD_RESPMEM_PERSISTENT:
        default:
            message->data = data;
            break;
    }

    return message;

error:
    destroy_message(message);
    return NULL;
}

static void destroy_message(struct message *message) {
    switch (message->respmem) {
        case MHD_RESPMEM_MUST_COPY:
        case MHD_RESPMEM_MUST_FREE:
            free(message->data);
            break;
        case MHD_RESPMEM_PERSISTENT:
        default:
            break;
    }
    free(message);
}

static void ref_message(struct message *message) {
    message->refcount++;
}

static void unref_message(struct message *message) {
    message->refcount--;
    if (message->refcount == 0) {
        destroy_message(message);
    }
}
