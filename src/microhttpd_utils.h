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
 * @file microhttpd_utils.h
 * Simple add-ons for microhttpd to take care of common needs.
 *
 * Takes care of stuff like request routing, parsing POST items, etc.
 */

#pragma once

#ifdef __ANDROID__
#  include <android/log.h>
#endif

#ifndef NDEBUG
#  ifdef __ANDROID__
#    define MHDU_LOG(M, ...) { __android_log_print(ANDROID_LOG_DEBUG, "MHDU", M, ##__VA_ARGS__); }
#  else
#    define MHDU_LOG(M, ...) { fprintf(stdout, "%s: " M "\n", __FUNCTION__, ##__VA_ARGS__); }
#  endif
#else
#  define MHDU_LOG(M, ...)
#endif

#ifdef __ANDROID__
#  define MHDU_ERR(M, ...) { __android_log_print(ANDROID_LOG_ERROR, "MHDU", M, ##__VA_ARGS__); }
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

typedef struct MHD_Response* (*MHDU_RequestRouteCallback)(void *cls,
        struct MHD_Connection *connection, const char *url, const char *method,
        struct MHDU_Connection *mhdu_con, int *code, void **conn_cls);

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

/** Creates a new router instance. */
struct MHDU_Router* MHDU_create_router(void);

void MHDU_destroy_router(struct MHDU_Router *router);

/**
 * @param url_pattern A regular expression pattern.  Caller retains ownership.
 * @param route       Caller retains ownership.
 * @param cls         Closure object passed to handlers.
 * @returns MHD_YES on success MHD_NO on failure.
 */
int MHDU_add_route(struct MHDU_Router *router, const char *pattern,
                   enum MHDU_METHOD methods, MHDU_RequestRouteCallback cb,
                   void *cls);

/** Set this as the MHD_AccessHandlerCallback in MHD_start_daemon. */
int MHDU_route(void *cls, struct MHD_Connection *connection, const char *url,
               const char *method, const char *version,
               const char *upload_data, size_t *upload_data_size,
               void **con_cls);

char** MHDU_connection_get_matches(const struct MHDU_Connection *mhdu_con,
                                   size_t *nmatches);

struct MHD_Daemon* MHDU_start_daemon(unsigned int flags, unsigned short port,
                                     struct MHDU_Router *router);
