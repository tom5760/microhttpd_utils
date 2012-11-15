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
 * @file microhttpd_router.h
 * Regular expression-based URL Routing and connection management.
 *
 * Takes care of stuff like request routing, parsing POST items, etc.
 */

#pragma once

#ifdef __ANDROID__
#  include <android/log.h>
#endif

#ifndef NDEBUG
#  ifdef __ANDROID__
#    define MHDU_LOG(M, ...) { __android_log_print(ANDROID_LOG_DEBUG, "MHDU_Router", M, ##__VA_ARGS__); }
#  else
#    define MHDU_LOG(M, ...) { fprintf(stderr, "%s: " M "\n", __FUNCTION__, ##__VA_ARGS__); }
#  endif
#else
#  define MHDU_LOG(M, ...)
#endif

#ifdef __ANDROID__
#  define MHDU_ERR(M, ...) { __android_log_print(ANDROID_LOG_ERROR, "MHDU_Router", M, ##__VA_ARGS__); }
#else
#  define MHDU_ERR(M, ...) { fprintf(stderr, "[ERROR] %s: " M "\n", __FUNCTION__, ##__VA_ARGS__); }
#endif

/* Forward declarations */
struct MHD_Connection;
struct MHD_Response;

/** Request router. */
struct MHDU_Router;

/** Stores per-connection data. */
struct MHDU_Connection;

/** Flags for MHDU_add_route. */
enum MHDU_METHOD {
    MHDU_METHOD_CONNECT = 1 << 0,
    MHDU_METHOD_DELETE  = 1 << 1,
    MHDU_METHOD_GET     = 1 << 2,
    MHDU_METHOD_HEAD    = 1 << 3,
    MHDU_METHOD_OPTIONS = 1 << 4,
    MHDU_METHOD_POST    = 1 << 5,
    MHDU_METHOD_PUT     = 1 << 6,
    MHDU_METHOD_TRACE   = 1 << 7,
};

/**
 * Request handler callback.
 *
 * @param      cls Closure object passed to MHDU_add_route.
 * @param      connection MHD connection object.
 * @param      url        The URL requested by the client.
 * @param      method     The HTTP method used by the client.
 * @param      mhdu_con   MHDU-sepcific connection information.
 * @param[out] code       The HTTP status code to return.
 * @param      con_cls    Can be set by callback to data that will be preserved
 *                        for this connection.
 * @returns An MHD_Response to return to the client.
 */
typedef struct MHD_Response* (*MHDU_RequestRouteCallback)(void *cls,
        struct MHD_Connection *connection, const char *url, const char *method,
        struct MHDU_Connection *mhdu_con, int *code, void **con_cls);

/** Callback to iterate over GET/POST attributes. */
typedef void (*MHDU_AttributeCallback)(void *cls, const char *key,
        const char *value, size_t length);

/** Creates a new router instance. */
struct MHDU_Router* MHDU_create_router(void);

void MHDU_destroy_router(struct MHDU_Router *router);

/**
 * Adds a request route handler.
 *
 * The pattern can be a regular expression including groups.  Use
 * MHDU_connection_get_matches() to get the array of strings corresponding to
 * the groups in the pattern.
 *
 * @param router  an MHDU_Router instance.
 * @param pattern A regular expression (groups allowed) to match.
 * @param methods A combination of flags to determine which HTTP methods this
 *                route should activate on.
 * @param cb      The callback function for when a route matches.
 * @param cls     Closure object passed to the callback.
 * @returns MHD_YES on success MHD_NO on failure.
 */
int MHDU_add_route(struct MHDU_Router *router, const char *pattern,
        enum MHDU_METHOD methods, MHDU_RequestRouteCallback cb, void *cls);

/**
 * An MHD_AccessHandlerCallback to process requests from MHD.
 *
 * Set this as the MHD_AccessHandlerCallback in MHD_start_daemon.
 */
int MHDU_route(void *cls, struct MHD_Connection *connection, const char *url,
        const char *method, const char *version, const char *upload_data,
        size_t *upload_data_size, void **con_cls);

/**
 * Returns an array of strings for each group of a route pattern match.
 *
 * @param[out] nmatches Filled in with the number of items in the array.
 */
char** MHDU_connection_get_matches(const struct MHDU_Connection *mhdu_con,
        size_t *nmatches);

/** Iterate over the attributes in a request. */
void MHDU_attributes_iter(const struct MHDU_Connection *mhdu_con,
        MHDU_AttributeCallback cb, void *cls);

/** Get a specific attribute in a request. */
void MHDU_attribute_get(const struct MHDU_Connection *mhdu_con,
        const char *key, const char **value, size_t *length);

/** Get the number of attributes in a request. */
unsigned int MHDU_attribute_count(const struct MHDU_Connection *mhdu_con);

/** Get a specific attribute in a request by index. */
void MHDU_attribute_index(const struct MHDU_Connection *mhdu_con,
        unsigned int index, const char **key, const char **value,
        size_t *length);

/** Starts the MHD daemon, setting up the router as the handler callback. */
struct MHD_Daemon* MHDU_start_daemon(unsigned int flags, unsigned short port,
        struct MHDU_Router *router);
