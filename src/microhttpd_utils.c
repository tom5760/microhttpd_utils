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
 * @file microhttpd_utils.c
 * Simple add-ons for microhttpd to take care of common needs.
 *
 * Takes care of stuff like request routing, parsing POST items, etc.
 */

#include <arpa/inet.h>
#include <pthread.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <microhttpd.h>

#include <uthash.h>
#include <utlist.h>
#include <utstring.h>

#include <tj_buffer.h>

#include "microhttpd_utils.h"

static const size_t POST_BUFFER_SIZE = 1024;
static const size_t COMET_BLOCK_SIZE = 80;

struct route {
    char *pattern;
    regex_t regex;

    enum MHDU_METHOD methods;

    MHDU_RequestRouteCallback callback;
    void *cls;

    /* Items kept in a singly-linked list. */
    struct route *next;
};

struct post_attribute {
    char *key;
    tj_buffer *value;

    /* Items kept in a hash table. */
    UT_hash_handle hh;
};

struct MHDU_Connection {
    struct MHD_Connection *connection;
    struct route *route;
    void *con_cls;

    char **matches;
    size_t nmatches;

    struct MHD_PostProcessor *post_processor;
    struct post_attribute *post_attributes;
};

struct MHDU_Router {
    struct route *routes;
};

struct queue_item {
    struct channel *channel;

    char *data;
    size_t length;
    enum MHD_ResponseMemoryMode respmem;

    int refcount;

    /* Items stored in a doubly-linked list. */
    struct queue_item *next;
    struct queue_item *prev;
};

struct channel {
    char *name;

    struct MHDU_PubSubManager *pubsub;

    int n_subscriptions;
    struct subscription *subscriptions;

    /* Reentrant lock for publishing. */
    pthread_mutex_t lock;

    /* Subscriptions wait for this condition to be broadcast. */
    pthread_cond_t cond;

    sig_atomic_t closed;

    struct queue_item *queue;

    /* Items kept in a hash table. */
    UT_hash_handle hh;
};

struct subscription {
    MHDU_PubSubCallback callback;
    void *cls;

    struct channel *channel;

    struct queue_item *current;
    size_t read_length;

    /* Items kept in a doubly-linked list. */
    struct subscription *prev;
    struct subscription *next;
};

struct MHDU_PubSubManager {
    struct channel *channels;
    pthread_mutex_t lock;
};

static struct route* create_route(const char *pattern,
        enum MHDU_METHOD methods, MHDU_RequestRouteCallback cb, void *cls);
static void destroy_route(struct route *route);

static struct MHDU_Connection* create_mhdu_connection(
        struct MHD_Connection *connection, const char *method);
static void destroy_mhdu_connection(struct MHDU_Connection *mhdu_con);
static int connection_set_route(struct MHDU_Connection *mhdu_con,
        struct route *route, const char *url, const regmatch_t *matches,
        size_t ngroups);

static struct post_attribute* create_post_attribute(const char *key);
static void destroy_post_attribute(struct post_attribute *attribute);

static int post_iterator(void *cls, enum MHD_ValueKind kind, const char *key,
        const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data, uint64_t off,
        size_t size);
static int post_iterator_meta(struct MHDU_Connection *mhdu_con,
        enum MHD_ValueKind kind, const char *key, const char *postfix,
        const char *value);

static int item_iterator(void *cls, enum MHD_ValueKind kind, const char *key,
        const char *value);

static void handle_request_complete(void *cls,
        struct MHD_Connection *connection, void **con_cls,
        enum MHD_RequestTerminationCode toe);

static struct MHD_Response* handle_404(int *code);
static struct MHD_Response* handle_500(int *code);

static struct channel* create_or_find_channel(
        struct MHDU_PubSubManager *pubsub, const char *name);
static void destroy_channel(struct channel *channel);

static struct subscription* create_subscription(struct channel *channel,
        MHDU_PubSubCallback cb, void *cls);
static void destroy_subscription(struct subscription *subscription);

static ssize_t pubsub_callback(void *cls, uint64_t pos, char *buf, size_t max);

static void pubsub_free_callback(void *cls);

static struct queue_item* create_queue_item(struct channel *channel,
        char *data, size_t length, enum MHD_ResponseMemoryMode respmem);
static void destroy_queue_item(struct queue_item *item);
static void ref_queue_item(struct queue_item *item);
static void deref_queue_item(struct queue_item *item);

/** client_addr_str should be of size INET_ADDRSTRLEN. */
static void get_client_addr_str(struct MHD_Connection *connection,
        char *client_addr_str);

struct MHDU_Router *MHDU_create_router(void) {
    struct MHDU_Router *router = calloc(1, sizeof(*router));
    if (router == NULL) {
        MHDU_ERR("Failed to allocate memory for router.");
        return NULL;
    }

    return router;
}

void MHDU_destroy_router(struct MHDU_Router *router) {
    struct route *route;
    struct route *tmp;
    LL_FOREACH_SAFE(router->routes, route, tmp) {
        LL_DELETE(router->routes, route);
        destroy_route(route);
    }

    free(router);
}

int MHDU_add_route(struct MHDU_Router *router, const char *pattern,
        enum MHDU_METHOD methods, MHDU_RequestRouteCallback cb,
        void *cls) {
    struct route *route = create_route(pattern, methods, cb, cls);
    if (route == NULL) {
        return MHD_NO;
    }

    LL_APPEND(router->routes, route);
    return MHD_YES;
}

int MHDU_route(void *cls, struct MHD_Connection *connection, const char *url,
        const char *method, const char *version, const char *upload_data,
        size_t *upload_data_size, void **con_cls) {
    struct MHDU_Router *router = (struct MHDU_Router*)cls;
    struct MHDU_Connection *mhdu_con = (struct MHDU_Connection*)*con_cls;

    struct MHD_Response *response = NULL;
    int code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    int rv = MHD_NO;

    struct route *route;

    char client_addr_str[INET_ADDRSTRLEN];
    get_client_addr_str(connection, client_addr_str);

    if (mhdu_con == NULL) {
        MHDU_LOG("New request from %s: %s %s", client_addr_str, method, url);
        *con_cls = mhdu_con = create_mhdu_connection(connection, method);
        if (mhdu_con == NULL) {
            return MHD_NO;
        }
        return MHD_YES;
    }

    MHDU_LOG("Continue request from %s: %s %s", client_addr_str, method, url);

    if (mhdu_con->route == NULL) {
        LL_FOREACH(router->routes, route) {
            MHDU_LOG("Checking route: %s", route->pattern);

            /* First entry is always the whole matched string, so +1. */
            size_t ngroups = route->regex.re_nsub + 1;
            regmatch_t matches[ngroups];

            int rv = regexec(&route->regex, url, ngroups, matches, 0);

            if (rv != 0 && rv != REG_NOMATCH) {
                char error[256];
                regerror(rv, &route->regex, error, 256);
                MHDU_ERR("Failed to match regular expression: %s", error);
                return MHD_NO;
            }

            if (rv == 0 && (((route->methods & MHDU_METHOD_CONNECT)
                            && strcmp(method, MHD_HTTP_METHOD_CONNECT) == 0)
                        || ((route->methods & MHDU_METHOD_DELETE)
                            && strcmp(method, MHD_HTTP_METHOD_DELETE) == 0)
                        || ((route->methods & MHDU_METHOD_GET)
                            && strcmp(method, MHD_HTTP_METHOD_GET) == 0)
                        || ((route->methods & MHDU_METHOD_HEAD)
                            && strcmp(method, MHD_HTTP_METHOD_HEAD) == 0)
                        || ((route->methods & MHDU_METHOD_POST)
                            && strcmp(method, MHD_HTTP_METHOD_POST) == 0)
                        || ((route->methods & MHDU_METHOD_PUT)
                            && strcmp(method, MHD_HTTP_METHOD_PUT) == 0)
                        || ((route->methods & MHDU_METHOD_TRACE)
                            && strcmp(method, MHD_HTTP_METHOD_TRACE) == 0))) {

                /* Found a route, break. */
                MHDU_LOG("Found route.");
                if (connection_set_route(mhdu_con, route, url, matches,
                            ngroups) != MHD_YES) {
                    return MHD_NO;
                }
                break;
            }

            if (rv == 0) {
                MHDU_LOG("Found route, wrong method.");
            }
        }
        /* No routes found, close the connection. */
        if (route == NULL) {
            MHDU_LOG("No route.");
            response = handle_404(&code);
            goto done;
        }
    } else {
        route = mhdu_con->route;
    }

    if (*upload_data_size > 0) {
        if (MHD_post_process(mhdu_con->post_processor, upload_data,
                    *upload_data_size) != MHD_YES) {
            MHDU_ERR("Error processing POST data.");
            return MHD_NO;
        }
        *upload_data_size = 0;
        return MHD_YES;
    }

    MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND,
            &item_iterator, mhdu_con);
    MHD_get_connection_values(connection, MHD_POSTDATA_KIND, &item_iterator,
            mhdu_con);

    response = route->callback(route->cls, connection, url, method, mhdu_con,
            &code, &mhdu_con->con_cls);
    if (response == NULL) {
        MHDU_LOG("NULL response from callback");
        response = handle_500(&code);
        goto done;
    }

done:
    rv = MHD_queue_response(connection, code, response);
    MHD_destroy_response(response);

    MHDU_LOG("Handled (%d) %s %s %s", code, client_addr_str, method, url);
    return rv;
}

char** MHDU_connection_get_matches(const struct MHDU_Connection *mhdu_con,
        size_t *nmatches) {
    *nmatches = mhdu_con->nmatches;
    return mhdu_con->matches;
}

void MHDU_attributes_iter(const struct MHDU_Connection *mhdu_con,
        MHDU_AttributeCallback cb, void *cls) {
    struct post_attribute *attribute;
    struct post_attribute *tmp;
    HASH_ITER(hh, mhdu_con->post_attributes, attribute, tmp) {
        cb(cls, attribute->key, tj_buffer_getAsString(attribute->value),
                tj_buffer_getUsed(attribute->value));
    }
}

void MHDU_attribute_get(const struct MHDU_Connection *mhdu_con,
        const char *key, const char **value, size_t *length) {
    struct post_attribute *attribute;
    HASH_FIND_STR(mhdu_con->post_attributes, key, attribute);
    if (attribute == NULL) {
        *value = NULL;
    }
    *value = tj_buffer_getAsString(attribute->value);
    *length = tj_buffer_getUsed(attribute->value);
}

struct MHD_Daemon* MHDU_start_daemon(unsigned int flags, unsigned short port,
        struct MHDU_Router *router) {
    return MHD_start_daemon(flags, port,
            /* MHD_AcceptPolicyCallback and data */
            NULL, NULL,
            /* MHD_AccessHandlerCallback and data */
            &MHDU_route, router,
            /* MHD_OPTIONs */
            MHD_OPTION_NOTIFY_COMPLETED,
            &handle_request_complete, NULL,
            MHD_OPTION_END);
}

struct MHDU_PubSubManager* MHDU_create_pubsub_manager(void) {
    struct MHDU_PubSubManager *pubsub = calloc(1, sizeof(*pubsub));
    if (pubsub == NULL) {
        MHDU_LOG("Failed allocating pubsub manager.");
        return NULL;
    }

    return pubsub;
}

void MHDU_destroy_pubsub_manager(struct MHDU_PubSubManager *pubsub) {
    if (pthread_mutex_lock(&pubsub->lock) != 0) {
        MHDU_LOG("Failed to aquire pubsub lock.");
    }

    struct channel *channel;
    struct channel *tmp;
    HASH_ITER(hh, pubsub->channels, channel, tmp) {
        HASH_DEL(pubsub->channels, channel);
        channel->closed = 1;
        if (pthread_cond_broadcast(&channel->cond) != 0) {
            MHDU_ERR("Failed to broadcast condition variable.");
        }
    }

    if (pthread_mutex_unlock(&pubsub->lock) != 0) {
        MHDU_LOG("Failed to release pubsub lock.");
    }

    pthread_mutex_destroy(&pubsub->lock);

    free(pubsub);
}

struct MHD_Response* MHDU_create_response_from_subscription(
        struct MHDU_PubSubManager *pubsub, struct MHDU_Connection *mhdu_con,
        const char *name, int *code, MHDU_PubSubCallback cb, void *cls) {

    struct channel *channel = create_or_find_channel(pubsub, name);
    if (channel == NULL) {
        return NULL;
    }

    struct subscription *subscription = create_subscription(channel, cb, cls);
    if (subscription == NULL) {
        return NULL;
    }

    *code = MHD_HTTP_OK;
    return MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
            COMET_BLOCK_SIZE, pubsub_callback, subscription,
            pubsub_free_callback);
}

int MHDU_publish_data(struct MHDU_PubSubManager *pubsub, const char *name,
        const char *data, size_t length, enum MHD_ResponseMemoryMode respmem) {
    struct channel *channel = create_or_find_channel(pubsub, name);
    if (channel == NULL) {
        return MHD_NO;
    }

    if (pthread_mutex_lock(&channel->lock) != 0) {
        MHDU_ERR("Failed to lock channel.");
        return MHD_NO;
    }

    if (channel->n_subscriptions > 0) {
        struct queue_item *item = create_queue_item(channel, (char*)data,
                length, respmem);
        if (item == NULL) {
            return MHD_NO;
        }

        DL_APPEND(channel->queue, item);
        if (pthread_cond_broadcast(&channel->cond) != 0) {
            MHDU_ERR("Failed to broadcast condition variable.");
        }
        MHDU_LOG("Published to channel %s", name);
    }

    if (pthread_mutex_unlock(&channel->lock) != 0) {
        MHDU_ERR("Failed to unlock channel.");
    }

    return MHD_YES;
}

static struct route* create_route(const char *pattern,
        enum MHDU_METHOD methods, MHDU_RequestRouteCallback cb, void *cls) {
    struct route *route = calloc(1, sizeof(*route));
    if (route == NULL) {
        MHDU_ERR("Failed to allocate memory for route.");
        return NULL;
    }

    route->methods = methods;
    route->callback = cb;
    route->cls = cls;

    route->pattern = strdup(pattern);
    if (route->pattern == NULL) {
        MHDU_ERR("Failed to copy route regex pattern.");
        goto error;
    }

    int rv = regcomp(&route->regex, pattern, 0);
    if (rv != 0) {
        char error[256];
        regerror(rv, &route->regex, error, 256);
        MHDU_ERR("Failed to compile regular expression: %s", error);
        goto error;
    }

    return route;

error:
    destroy_route(route);
    return NULL;
}

static void destroy_route(struct route *route) {
    free(route->pattern);
    regfree(&route->regex);
    free(route);
}

static struct MHDU_Connection* create_mhdu_connection(
        struct MHD_Connection *connection, const char *method) {
    struct MHDU_Connection *mhdu_con = calloc(1, sizeof(*mhdu_con));
    if (mhdu_con == NULL) {
        MHDU_ERR("Failed to allocate memory for MHDU connection.");
        return NULL;
    }

    mhdu_con->connection = connection;
    mhdu_con->con_cls = NULL;

    if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
        mhdu_con->post_processor = MHD_create_post_processor(connection,
                POST_BUFFER_SIZE, &post_iterator, mhdu_con);
        if (mhdu_con->post_processor == NULL) {
            MHDU_ERR("Failed to create POST processor.");
            goto error;
        }
    }

    return mhdu_con;

error:
    destroy_mhdu_connection(mhdu_con);
    return NULL;
}

static void destroy_mhdu_connection(struct MHDU_Connection *mhdu_con) {
    if (mhdu_con->matches != NULL) {
        for (unsigned int i = 0; i < mhdu_con->nmatches; i++) {
            free(mhdu_con->matches[i]);
        }
        free(mhdu_con->matches);
    }
    MHD_destroy_post_processor(mhdu_con->post_processor);

    struct post_attribute *attribute;
    struct post_attribute *tmp;
    HASH_ITER(hh, mhdu_con->post_attributes, attribute, tmp) {
        HASH_DEL(mhdu_con->post_attributes, attribute);
        destroy_post_attribute(attribute);
    }

    free(mhdu_con);
}

static int connection_set_route(struct MHDU_Connection *mhdu_con,
        struct route *route, const char *url, const regmatch_t *matches,
        size_t ngroups) {
    mhdu_con->route = route;

    mhdu_con->nmatches = ngroups;
    mhdu_con->matches = calloc(ngroups, sizeof(char*));
    if (mhdu_con->matches == NULL) {
        MHDU_ERR("Failed to allocate memory for regex matches.");
        goto error;
    }
    for (unsigned int i = 0; i < ngroups; i++) {
        mhdu_con->matches[i] = strndup(url + matches[i].rm_so,
                matches[i].rm_eo - matches[i].rm_so);
        if (mhdu_con->matches[i] == NULL) {
            MHDU_ERR("Failed to duplicate regex match.");
            goto error;
        }
    }

    return MHD_YES;

error:
    destroy_mhdu_connection(mhdu_con);
    return MHD_NO;
}

static struct post_attribute* create_post_attribute(const char *key) {
    struct post_attribute *attribute = calloc(1, sizeof(*attribute));
    if (attribute == NULL) {
        MHDU_ERR("Failed to allocate POST attribute.");
        return NULL;
    }

    attribute->key = strdup(key);
    if (attribute->key == NULL) {
        MHDU_ERR("Failed to duplicate POST attribute key.");
        goto error;
    }

    attribute->value = tj_buffer_create(0);
    if (attribute->value == NULL) {
        MHDU_ERR("Failed to allocate POST attribute value buffer.");
        goto error;
    }

    return attribute;

error:
    destroy_post_attribute(attribute);
    return NULL;
}

static void destroy_post_attribute(struct post_attribute *attribute) {
    if (attribute->value != NULL) {
        tj_buffer_finalize(attribute->value);
    }
    free(attribute->key);
    free(attribute);
}

static int post_iterator(void *cls, enum MHD_ValueKind kind, const char *key,
        const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data, uint64_t off,
        size_t size) {
    struct MHDU_Connection *mhdu_con = (struct MHDU_Connection*)cls;

    if (key == NULL || key[0] == '\0') {
        MHDU_ERR("No key to iterate.");
        return MHD_NO;
    }

    MHDU_LOG("POST processing: %s", key);

    if (data == NULL || size == 0) {
        return MHD_YES;
    }

    struct post_attribute *attribute;
    HASH_FIND_STR(mhdu_con->post_attributes, key, attribute);
    if (attribute == NULL) {
        if ((attribute = create_post_attribute(key)) == NULL) {
            MHDU_ERR("Could not create key value pair.");
            return MHD_NO;
        }
        HASH_ADD_KEYPTR(hh, mhdu_con->post_attributes, attribute->key,
                strlen(attribute->key), attribute);
    }

    if (tj_buffer_append(attribute->value, (const tj_buffer_byte*)data, size)
            != 1) {
        MHDU_ERR("Could not append data to POST attribute.");
        goto error;
    }

    if (post_iterator_meta(mhdu_con, kind, key, "_filename", filename)
            != MHD_YES) {
        MHDU_ERR("Could not set filename POST attribute.");
        goto error;
    }

    if (post_iterator_meta(mhdu_con, kind, key, "_content_type", content_type)
            != MHD_YES) {
        MHDU_ERR("Could not set content_type POST attribute.");
        goto error;
    }

    if (post_iterator_meta(mhdu_con, kind, key, "_transfer_encoding",
                transfer_encoding) != MHD_YES) {
        MHDU_ERR("Could not set transfer_encoding POST attribute.");
        goto error;
    }

    return MHD_YES;

error:
    HASH_DEL(mhdu_con->post_attributes, attribute);
    destroy_post_attribute(attribute);
    return MHD_NO;
}

static int post_iterator_meta(struct MHDU_Connection *mhdu_con,
        enum MHD_ValueKind kind, const char *key, const char *postfix,
        const char *value) {
    if (value == NULL || value[0] == '\0') {
        return MHD_YES;
    }

    UT_string new_key;
    utstring_init(&new_key);
    utstring_printf(&new_key, "%s%s", key, postfix);

    struct post_attribute *tmp;
    HASH_FIND_STR(mhdu_con->post_attributes, utstring_body(&new_key), tmp);
    if (tmp == NULL) {
        if (post_iterator(mhdu_con, kind, utstring_body(&new_key), NULL, NULL,
                    NULL, value, 0, strlen(value)) != MHD_YES) {
            utstring_done(&new_key);
            return MHD_NO;
        }
    } else if (strcmp(tj_buffer_getAsString(tmp->value), value) != 0) {
        MHDU_ERR("Mismatched values for key %s: %s, %s", key, value,
                tj_buffer_getAsString(tmp->value));
    }

    utstring_done(&new_key);
    return MHD_YES;
}

static int item_iterator(void *cls, enum MHD_ValueKind kind, const char *key,
        const char *value) {
    return post_iterator(cls, kind, key, NULL, NULL, NULL, value, 0,
            strlen(value));
}

static void handle_request_complete(void *cls,
        struct MHD_Connection *connection, void **con_cls,
        enum MHD_RequestTerminationCode toe) {
    struct MHDU_Connection *mhdu_con = (struct MHDU_Connection*)*con_cls;

    MHDU_LOG("ASDF");

    if (mhdu_con != NULL) {
        destroy_mhdu_connection(mhdu_con);
    }

    switch (toe) {
        case MHD_REQUEST_TERMINATED_WITH_ERROR:
            MHDU_ERR("Request terminated: error");
            break;
        case MHD_REQUEST_TERMINATED_TIMEOUT_REACHED:
            MHDU_ERR("Request terminated: timeout reached");
            break;
        default:
            break;
    }
}

static void get_client_addr_str(struct MHD_Connection *connection,
        char *client_addr_str) {
    const union MHD_ConnectionInfo *info = MHD_get_connection_info(
            connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    inet_ntop(AF_INET, &((struct sockaddr_in*)info->client_addr)->sin_addr,
            client_addr_str, INET_ADDRSTRLEN);
}

static struct MHD_Response* handle_404(int *code) {
    static const char *page = "404 NOT FOUND";
    *code = MHD_HTTP_NOT_FOUND;
    return MHD_create_response_from_buffer(strlen(page), (void*)page,
            MHD_RESPMEM_PERSISTENT);
}

static struct MHD_Response* handle_500(int *code) {
    static const char *page = "500 INTERNAL SERVER ERROR";
    *code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    return MHD_create_response_from_buffer(strlen(page), (void*)page,
            MHD_RESPMEM_PERSISTENT);
}

static struct channel* create_or_find_channel(
        struct MHDU_PubSubManager *pubsub, const char *name) {
    if (pthread_mutex_lock(&pubsub->lock) != 0) {
        MHDU_LOG("Failed to aquire pubsub lock.");
        return NULL;
    }

    struct channel *channel;
    HASH_FIND_STR(pubsub->channels, name, channel);
    if (channel == NULL) {
        MHDU_LOG("New channel: %s", name);
        channel = calloc(1, sizeof(*channel));
        if (channel == NULL) {
            MHDU_ERR("Failed to allocate memory for channel.");
            goto error;
        }

        channel->name = strdup(name);
        if (channel->name == NULL) {
            MHDU_ERR("Failed to duplicate name for channel.");
            goto error;
        }

        pthread_mutexattr_t attr;
        if (pthread_mutexattr_init(&attr) != 0) {
            MHDU_ERR("Failed to create mutex attribute.");
            goto error;
        }

        if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
            MHDU_ERR("Failed to set recursive mutex type.");
            goto error;
        }

        if (pthread_mutex_init(&channel->lock, &attr) != 0) {
            MHDU_ERR("Failed to create publish lock.");
            goto error;
        }

        if (pthread_mutexattr_destroy(&attr) != 0) {
            MHDU_ERR("Failed to destroy mutex attribute.");
            /* not a fatal error. */
        }

        channel->pubsub = pubsub;

        channel->n_subscriptions = 0;
        channel->subscriptions = NULL;

        channel->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

        HASH_ADD_KEYPTR(hh, pubsub->channels, channel->name,
                strlen(channel->name), channel);
    }

    if (pthread_mutex_unlock(&pubsub->lock) != 0) {
        MHDU_LOG("Failed to release pubsub lock.");
    }

    return channel;

error:
    if (pthread_mutex_unlock(&pubsub->lock) != 0) {
        MHDU_LOG("Failed to release pubsub lock.");
    }

    channel->pubsub = NULL;
    destroy_channel(channel);
    return NULL;
}

static void destroy_channel(struct channel *channel) {
    channel->closed = 1;

    if (channel->pubsub != NULL) {
        if (pthread_mutex_lock(&channel->pubsub->lock) != 0) {
            MHDU_LOG("Failed to aquire pubsub lock.");
        }
        HASH_DEL(channel->pubsub->channels, channel);
        if (pthread_mutex_unlock(&channel->pubsub->lock) != 0) {
            MHDU_LOG("Failed to release pubsub lock.");
        }
        channel->pubsub = NULL;
    }

    if (channel->n_subscriptions > 0) {
        if (pthread_cond_broadcast(&channel->cond) != 0) {
            MHDU_ERR("Failed to broadcast condition variable.");
        }
        MHDU_LOG("Some subscriptions still running.");
        return;
    }

    pthread_mutex_destroy(&channel->lock);
    pthread_cond_destroy(&channel->cond);

    free(channel->name);
    free(channel);
}

static struct subscription* create_subscription(struct channel *channel,
        MHDU_PubSubCallback cb, void *cls) {
    struct subscription *subscription = calloc(1, sizeof(*subscription));
    if (subscription == NULL) {
        MHDU_LOG("Failed to allocate subscription.");
        return NULL;
    }

    subscription->channel = channel;
    subscription->callback = cb;
    subscription->cls = cls;

    if (pthread_mutex_lock(&channel->lock) != 0) {
        MHDU_ERR("Failed to lock channel.");
    }

    DL_APPEND(channel->subscriptions, subscription);
    channel->n_subscriptions++;

    if (pthread_mutex_unlock(&channel->lock) != 0) {
        MHDU_ERR("Failed to unlock channel.");
    }

    return subscription;
}

static void destroy_subscription(struct subscription *subscription) {
    struct channel *channel = subscription->channel;

    if (subscription->current != NULL) {
        deref_queue_item(subscription->current);
    }

    if (channel != NULL) {
        if (pthread_mutex_lock(&channel->lock) != 0) {
            MHDU_ERR("Failed to lock channel.");
        }

        DL_DELETE(channel->subscriptions, subscription);
        channel->n_subscriptions--;

        if (channel->n_subscriptions <= 0) {
            MHDU_LOG("No subscriptions left, destroying channel.");

            if (pthread_mutex_unlock(&channel->lock) != 0) {
                MHDU_ERR("Failed to unlock channel.");
            }
            destroy_channel(channel);
        } else {
            if (pthread_mutex_unlock(&channel->lock) != 0) {
                MHDU_ERR("Failed to unlock channel.");
            }
        }
    }

    free(subscription);

}

static ssize_t pubsub_callback(void *cls, uint64_t pos, char *buf,
        size_t max) {
    struct subscription *subscription = (struct subscription*)cls;
    ssize_t rv = 0;

    if (subscription->channel->closed) {
        MHDU_LOG("Channel shutting down.");
        rv = MHD_CONTENT_READER_END_OF_STREAM;
        destroy_subscription(subscription);
        goto done;
    }

    if ((subscription->current == NULL)
            || (subscription->read_length == subscription->current->length)) {
        if (pthread_mutex_lock(&subscription->channel->lock) != 0) {
            MHDU_ERR("Failed to lock channel.");
            return MHD_CONTENT_READER_END_WITH_ERROR;
        }

        if ((subscription->channel->queue == NULL)
                || (subscription->channel->queue == subscription->current)) {
            MHDU_LOG("Waiting for new item");
            if (pthread_cond_wait(&subscription->channel->cond,
                        &subscription->channel->lock) != 0) {
                MHDU_ERR("Failed to wait for condition.");
                return MHD_CONTENT_READER_END_WITH_ERROR;
            }
        }

        if (subscription->channel->closed) {
            MHDU_LOG("Channel shutting down.");
            rv = MHD_CONTENT_READER_END_OF_STREAM;
            destroy_subscription(subscription);
            goto done;
        }

        MHDU_LOG("New item!");
        subscription->current = subscription->channel->queue;
        subscription->read_length = 0;
        ref_queue_item(subscription->current);

        if (pthread_mutex_unlock(&subscription->channel->lock) != 0) {
            MHDU_ERR("Failed to unlock channel.");
            return MHD_CONTENT_READER_END_WITH_ERROR;
        }
    }

    rv = subscription->callback(subscription->cls, subscription->channel->name,
            subscription->current->data, subscription->current->length,
            subscription->read_length, buf, max);
    subscription->read_length += rv;

    if (subscription->read_length == subscription->current->length) {
        deref_queue_item(subscription->current);
    }

    MHDU_LOG("Read: %zd/%zd", subscription->read_length,
            subscription->current->length);

done:
    return rv;
}

static void pubsub_free_callback(void *cls) {
    destroy_subscription((struct subscription*)cls);
}

static struct queue_item* create_queue_item(struct channel *channel,
        char *data, size_t length, enum MHD_ResponseMemoryMode respmem) {
    struct queue_item *item = calloc(1, sizeof(*item));
    if (item == NULL) {
        MHDU_ERR("Failed to allocate queue item.");
        return NULL;
    }

    item->channel = channel;
    item->refcount = 0;

    item->length = length;
    item->respmem = respmem;
    switch (respmem) {
        case MHD_RESPMEM_PERSISTENT:
        case MHD_RESPMEM_MUST_FREE:
            item->data = data;
            break;
        case MHD_RESPMEM_MUST_COPY:
            item->data = malloc(length);
            if (item->data == NULL) {
                MHDU_ERR("Failed to copy queue item data.");
                goto error;
            }
            memcpy(item->data, data, length);
            break;
        default:
            MHDU_ERR("Invalid queue item memory mode.");
            goto error;
    }

    return item;

error:
    item->channel = NULL;
    destroy_queue_item(item);
    return NULL;
}

static void destroy_queue_item(struct queue_item *item) {
    struct channel *channel = item->channel;

    if (channel != NULL) {
        if (pthread_mutex_lock(&channel->lock) != 0) {
            MHDU_ERR("Failed to lock channel.");
        }
        DL_DELETE(channel->queue, item);
        if (pthread_mutex_unlock(&channel->lock) != 0) {
            MHDU_ERR("Failed to unlock channel.");
        }
    }

    switch (item->respmem) {
        case MHD_RESPMEM_MUST_FREE:
        case MHD_RESPMEM_MUST_COPY:
            free(item->data);
            break;
        case MHD_RESPMEM_PERSISTENT:
        default:
            break;
    }
    free(item);
}

static void ref_queue_item(struct queue_item *item) {
    if (pthread_mutex_lock(&item->channel->lock) != 0) {
        MHDU_ERR("Failed to lock channel.");
    }
    item->refcount++;
    if (pthread_mutex_unlock(&item->channel->lock) != 0) {
        MHDU_ERR("Failed to unlock channel.");
    }
}

static void deref_queue_item(struct queue_item *item) {
    struct channel *channel = item->channel;
    if (channel != NULL && pthread_mutex_lock(&channel->lock) != 0) {
        MHDU_ERR("Failed to lock channel.");
    }
    item->refcount--;
    MHDU_LOG("REFCOUNT: %d", item->refcount);
    if (item->refcount == 0) {
        destroy_queue_item(item);
    }
    if (channel != NULL && pthread_mutex_unlock(&channel->lock) != 0) {
        MHDU_ERR("Failed to unlock channel.");
    }
}
