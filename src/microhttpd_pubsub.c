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

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

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
    /** The pubsub instance this subscription is on. */
    struct MHDU_PubSub *pubsub;

    MHDU_PubSubCallback callback;
    MHDU_PubSubCleanupCallback cleanup;
    void *cls;

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

/** Holds all the subscribers to a particular pubsub instance. */
struct MHDU_PubSub {
    /** The subscriptions on this channel. */
    struct subscription *subs;

    /** Number of subscriptions. */
    unsigned int num_subs;

    /** Lock protecting access to subscriptions. */
    pthread_mutex_t lock;

    /** Whether this pubsub instance has shut down. */
    bool closed;
};

static void destroy_pubsub(struct MHDU_PubSub *pubsub);

static ssize_t pubsub_callback(void *cls, uint64_t pos, char *buf, size_t max);
static void pubsub_free_callback(void *cls);

static struct subscription* create_subscription(struct MHDU_PubSub *pubsub,
        MHDU_PubSubCallback callback, MHDU_PubSubCleanupCallback cleanup,
        void *cls);
static void destroy_subscription(struct subscription *sub);

static struct queue_item* create_queue_item(struct message *message);
static void destroy_queue_item(struct queue_item *item);

static struct message* create_message(char *data, size_t length,
        enum MHD_ResponseMemoryMode respmem);
static void destroy_message(struct message *message);

static void ref_message(struct message *message);
static void unref_message(struct message *message);

struct MHDU_PubSub* MHDU_start_pubsub(void) {
    struct MHDU_PubSub *pubsub = calloc(1, sizeof(*pubsub));
    if (pubsub == NULL) {
        MHDU_ERR("Failed to allocate pubsub.");
        return NULL;
    }

    pubsub->num_subs = 0;
    pubsub->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    pubsub->closed = false;

    return pubsub;
}

void MHDU_stop_pubsub(struct MHDU_PubSub *pubsub) {
    pthread_mutex_lock(&pubsub->lock);
    pubsub->closed = true;
    struct subscription *sub, *tmp;
    DL_FOREACH_SAFE(pubsub->subs, sub, tmp) {
        pthread_cond_broadcast(&sub->cond);
    }
    pthread_mutex_unlock(&pubsub->lock);
}

struct MHD_Response* MHDU_create_response_from_subscription(
        struct MHDU_PubSub *pubsub, struct MHDU_Connection *mhdu_con,
        int *code, MHDU_PubSubCallback cb, MHDU_PubSubCleanupCallback cleanup,
        void *cls) {
    pthread_mutex_lock(&pubsub->lock);
    struct subscription *sub = create_subscription(pubsub, cb, cleanup, cls);
    if (sub == NULL) {
        pthread_mutex_unlock(&pubsub->lock);
        return NULL;
    }
    DL_APPEND(pubsub->subs, sub);
    pubsub->num_subs++;
    pthread_mutex_unlock(&pubsub->lock);

    *code = MHD_HTTP_OK;
    return MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
            PUBSUB_BLOCK_SIZE, pubsub_callback, sub, pubsub_free_callback);
}

int MHDU_publish_data(struct MHDU_PubSub *pubsub, const char *data,
        size_t length, enum MHD_ResponseMemoryMode respmem) {
    pthread_mutex_lock(&pubsub->lock);
    if (pubsub->num_subs == 0) {
        pthread_mutex_unlock(&pubsub->lock);
        /* No subscribers, not an error. */
        return MHD_YES;
    }

    struct message *msg = create_message((char*)data, length, respmem);
    if (msg == NULL) {
        MHDU_LOG("Failed to create message.");
        return MHD_NO;
    }

    struct subscription *sub, *tmp;
    DL_FOREACH_SAFE(pubsub->subs, sub, tmp) {
        struct queue_item *item = create_queue_item(msg);
        if (item == NULL) {
            MHDU_LOG("Failed to create queue item.");
            continue;
        }
        pthread_mutex_lock(&sub->lock);
        DL_APPEND(sub->queue, item);
        pthread_cond_broadcast(&sub->cond);
        pthread_mutex_unlock(&sub->lock);
    }
    pthread_mutex_unlock(&pubsub->lock);

    return MHD_YES;
}

ssize_t MHDU_PubSubPassthroughCallback(void *cls, const char *data,
        size_t data_length, size_t offset, char *buf, size_t max) {
    size_t n = 0;
    if (data_length < max) {
        n = data_length;
    } else {
        n = max;
    }
    memcpy(buf, data, n);
    return n;
}

static void destroy_pubsub(struct MHDU_PubSub *pubsub) {
    pthread_mutex_lock(&pubsub->lock);
    if (!pubsub->closed) {
        MHDU_ERR("Pubsub not closed!");
    }
    if (pubsub->num_subs > 0) {
        MHDU_ERR("Pubsub not empty!");
    }
    pthread_mutex_unlock(&pubsub->lock);
    pthread_mutex_destroy(&pubsub->lock);
    free(pubsub);
}

static ssize_t pubsub_callback(void *cls, uint64_t pos, char *buf,
        size_t max) {
    struct subscription *sub = (struct subscription*)cls;
    struct MHDU_PubSub *pubsub = sub->pubsub;

    pthread_mutex_lock(&pubsub->lock);
    if (sub->pubsub->closed) {
        pthread_mutex_unlock(&pubsub->lock);
        return MHD_CONTENT_READER_END_OF_STREAM;
    } else {
        pthread_mutex_unlock(&pubsub->lock);
    }

    pthread_mutex_lock(&sub->lock);
    if (sub->queue == NULL) {
        pthread_cond_wait(&sub->cond, &sub->lock);

        /* Nobody removes items from the queue except for this function, so its
         * safe to look at the first item without a lock. */
        pthread_mutex_unlock(&sub->lock);

        pthread_mutex_lock(&pubsub->lock);
        if (sub->pubsub->closed) {
            pthread_mutex_unlock(&pubsub->lock);
            return MHD_CONTENT_READER_END_OF_STREAM;
        } else {
            pthread_mutex_unlock(&pubsub->lock);
        }
    }

    struct queue_item *item = sub->queue;
    struct message *message = item->message;

    size_t rv = sub->callback(sub->cls, message->data, message->length,
            item->num_read, buf, max);
    item->num_read += rv;

    if (item->num_read == message->length) {
        pthread_mutex_lock(&sub->lock);
        /* Pop the top element off the queue. */
        DL_DELETE(sub->queue, item);
        pthread_mutex_unlock(&sub->lock);

        pthread_mutex_lock(&sub->pubsub->lock);
        destroy_queue_item(item);
        pthread_mutex_unlock(&sub->pubsub->lock);
    }

    return rv;
}

static void pubsub_free_callback(void *cls) {
    destroy_subscription((struct subscription*)cls);
}

static struct subscription* create_subscription(struct MHDU_PubSub *pubsub,
        MHDU_PubSubCallback callback, MHDU_PubSubCleanupCallback cleanup,
        void *cls) {
    struct subscription *sub = calloc(1, sizeof(*sub));
    if (sub == NULL) {
        MHDU_ERR("Failed to allocate sub.");
        return NULL;
    }

    sub->pubsub = pubsub;
    sub->callback = callback;
    sub->cleanup = cleanup;
    sub->cls = cls;

    sub->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    sub->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

    return sub;
}

static void destroy_subscription(struct subscription *sub) {
    if (sub->cleanup != NULL) {
        sub->cleanup(sub->cls);
    }

    pthread_mutex_lock(&sub->lock);
    struct queue_item *item, *item_tmp;
    DL_FOREACH_SAFE(sub->queue, item, item_tmp) {
        DL_DELETE(sub->queue, item);
        destroy_queue_item(item);
    }
    pthread_mutex_unlock(&sub->lock);

    pthread_mutex_lock(&sub->pubsub->lock);
    DL_DELETE(sub->pubsub->subs, sub);
    sub->pubsub->num_subs--;
    if (sub->pubsub->num_subs == 0 && sub->pubsub->closed) {
        pthread_mutex_unlock(&sub->pubsub->lock);
        destroy_pubsub(sub->pubsub);
    } else {
        pthread_mutex_unlock(&sub->pubsub->lock);
    }

    pthread_cond_destroy(&sub->cond);
    pthread_mutex_destroy(&sub->lock);
    free(sub);
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
