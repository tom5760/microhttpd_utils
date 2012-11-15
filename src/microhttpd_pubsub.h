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

#pragma once

#ifdef __ANDROID__
#  include <android/log.h>
#endif

#ifndef NDEBUG
#  ifdef __ANDROID__
#    define MHDU_LOG(M, ...) { __android_log_print(ANDROID_LOG_DEBUG, "MHDU_PubSub", M, ##__VA_ARGS__); }
#  else
#    define MHDU_LOG(M, ...) { fprintf(stderr, "%s: " M "\n", __FUNCTION__, ##__VA_ARGS__); }
#  endif
#else
#  define MHDU_LOG(M, ...)
#endif

#ifdef __ANDROID__
#  define MHDU_ERR(M, ...) { __android_log_print(ANDROID_LOG_ERROR, "MHDU_PubSub", M, ##__VA_ARGS__); }
#else
#  define MHDU_ERR(M, ...) { fprintf(stderr, "[ERROR] %s: " M "\n", __FUNCTION__, ##__VA_ARGS__); }
#endif

/* Forward declarations */
struct MHD_Connection;
struct MHD_Response;
struct MHDU_Connection;

/** Stores data about groups of long-lived connections. */
struct MHDU_PubSub;

/**
 * Callback when a subscription fires.
 *
 * @param data        Published data.
 * @param data_length Total size of published data.
 * @param offset      Amount read by previous calls to this callback.
 * @param buf         Buffer to copy data to send to the client.
 * @param max         Maximum amount of data that can be copied to buf.
 * @returns Amount of data written to buf.
 */
typedef ssize_t (*MHDU_PubSubCallback)(void *cls, const char *data,
        size_t data_length, size_t offset, char *buf, size_t max);

struct MHDU_PubSub* MHDU_start_pubsub(void);

void MHDU_stop_pubsub(struct MHDU_PubSub *pubsub);

/**
 * Creates an response that will call cb when data is published to the channel.
 *
 * @param chan_name Name of the channel to subscribe to.
 * @param[out] code Pointer to HTTP return code to set.
 */
struct MHD_Response* MHDU_create_response_from_subscription(
        struct MHDU_PubSub *pubsub, struct MHDU_Connection *mhdu_con,
        int *code, MHDU_PubSubCallback cb, void *cls);

/**
 * Asynchronously send data to a channel.
 *
 * @param chan_name Name of the channel to publish to.
 * @param respmem   How to treat the data being published.
 */
int MHDU_publish_data(struct MHDU_PubSub *pubsub, const char *data,
        size_t length, enum MHD_ResponseMemoryMode respmem);

/** Callback that passes data directly to client. */
ssize_t MHDU_PubSubPassthroughCallback(void *cls, const char *data,
        size_t data_length, size_t offset, char *buf, size_t max);
