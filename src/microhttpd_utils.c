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
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <microhttpd.h>

#include <utlist.h>

#include "microhttpd_utils.h"

static const size_t POST_BUFFER_SIZE = 1024;

struct route {
    char *pattern;
    regex_t regex;

    enum MHDU_METHOD methods;

    MHDU_RequestRouteCallback callback;
    void *cls;

    /* Items kept in a singly-linked list. */
    struct route *next;
};

struct MHDU_Connection {
    struct MHD_Connection *connection;
    struct route *route;
    void *con_cls;

    char **matches;
    size_t nmatches;

    struct MHD_PostProcessor *post_processor;
};

struct MHDU_Router {
    struct route *routes;
};

static struct route* create_route(const char *pattern,
                                  enum MHDU_METHOD methods,
                                  MHDU_RequestRouteCallback cb, void *cls);
static void destroy_route(struct route *route);

static struct MHDU_Connection* create_mhdu_connection(
        struct MHD_Connection *connection, struct route *route,
        const char *method, const char *url, const regmatch_t *matches,
        size_t ngroups);
static void destroy_mhdu_connection(struct MHDU_Connection *mhdu_con);

static int post_iterator(void *cls, enum MHD_ValueKind kind, const char *key,
        const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data, uint64_t off,
        size_t size);

static void handle_request_complete(void *cls,
        struct MHD_Connection *connection, void **con_cls,
        enum MHD_RequestTerminationCode toe);

static struct MHD_Response* handle_404(int *code);
static struct MHD_Response* handle_500(int *code);

/** client_addr_str should be of size INET_ADDRSTRLEN. */
static void get_client_addr_str(
        struct MHD_Connection *connection, char *client_addr_str);

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
               const char *method, const char *version,
               const char *upload_data, size_t *upload_data_size,
               void **con_cls) {
    struct MHDU_Router *router = (struct MHDU_Router*)cls;
    struct MHDU_Connection *mhdu_con = (struct MHDU_Connection*)*con_cls;

    struct MHD_Response *response = NULL;
    int code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    int rv = MHD_NO;

    struct route *route;

    char client_addr_str[INET_ADDRSTRLEN];
    get_client_addr_str(connection, client_addr_str);

    if (mhdu_con != NULL) {
        MHDU_LOG("Continue request from %s: %s %s", client_addr_str, method,
                 url);
        route = mhdu_con->route;
    } else {
        MHDU_LOG("New request from %s: %s %s", client_addr_str, method, url);

        LL_FOREACH(router->routes, route) {
            MHDU_LOG("Checking route: %s", route->pattern);

            /* First entry is always the whole matched string, so +1. */
            size_t groups = route->regex.re_nsub + 1;
            regmatch_t matches[groups];

            int rv = regexec(&route->regex, url, groups, matches, 0);

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

                *con_cls = mhdu_con = create_mhdu_connection(connection,
                        route, method, url, matches, groups);
                if (mhdu_con == NULL) {
                    return MHD_NO;
                }

                /* Found a route, break. */
                MHDU_LOG("Found route.");
                break;
            }
        }
        /* No routes found, close the connection. */
        if (route == NULL) {
            MHDU_LOG("No route.");
            response = handle_404(&code);
            goto done;
        }
    }

    if (*upload_data_size > 0) {
        if (MHD_post_process(mhdu_con->post_processor, upload_data,
                             *upload_data_size) != MHD_YES) {
            MHDU_ERR("Error processing POST data.");
            destroy_mhdu_connection(mhdu_con);
            return MHD_NO;
        }
        *upload_data_size = 0;
        return MHD_YES;
    }

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

static struct route* create_route(const char *pattern,
                                  enum MHDU_METHOD methods,
                                  MHDU_RequestRouteCallback cb, void *cls) {
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
        struct MHD_Connection *connection, struct route *route,
        const char *method, const char *url, const regmatch_t *matches,
        size_t ngroups) {
    struct MHDU_Connection *mhdu_con = calloc(1, sizeof(*mhdu_con));
    if (mhdu_con == NULL) {
        MHDU_ERR("Failed to allocate memory for MHDU connection.");
        return NULL;
    }

    mhdu_con->connection = connection;
    mhdu_con->route = route;

    mhdu_con->con_cls = NULL;

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
    free(mhdu_con);
}

static int post_iterator(void *cls, enum MHD_ValueKind kind, const char *key,
        const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data, uint64_t off,
        size_t size) {
    return MHD_YES;
}

static void handle_request_complete(void *cls,
        struct MHD_Connection *connection, void **con_cls,
        enum MHD_RequestTerminationCode toe) {
    struct MHDU_Connection *mhdu_con = (struct MHDU_Connection*)*con_cls;

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

static void get_client_addr_str(
        struct MHD_Connection *connection, char *client_addr_str) {
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
