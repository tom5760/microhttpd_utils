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
 * @file test1.c
 * Testing microhttpd_utils
 */

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <utstring.h>

#include <microhttpd.h>
#include "microhttpd_router.h"
#include "microhttpd_pubsub.h"

static const uint16_t DEFAULT_PORT = 6892;

static int wait_fd;

static void signal_handler(int signal) {
    static const uint64_t x = 1;
    if (write(wait_fd, &x, sizeof(x)) == -1) {
        MHDU_ERR("Failed to write to event file descriptor.");
    }
}

static struct MHD_Response* test_get1(void *cls,
        struct MHD_Connection *connection, const char *url, const char *method,
        struct MHDU_Connection *mhdu_con, int *code, void **conn_cls) {
    UT_string page;
    utstring_init(&page);

    size_t nmatches = 0;
    char **matches = MHDU_connection_get_matches(mhdu_con, &nmatches);

    utstring_printf(&page,
            "<html><body><p>Hello world: %s</p><p>%zd matches</p><ul>",
            url, nmatches);

    for (unsigned int i = 0; i < nmatches; i++) {
        utstring_printf(&page, "\t<li>%s</li>\n", matches[i]);
    }
    utstring_printf(&page, "</ul><p>POST attributes:</p><ul>");

    *code = MHD_HTTP_OK;
    return MHD_create_response_from_buffer(utstring_len(&page),
            utstring_body(&page), MHD_RESPMEM_MUST_FREE);
}

static struct MHD_Response* publish_get(void *cls,
        struct MHD_Connection *connection, const char *url, const char *method,
        struct MHDU_Connection *mhdu_con, int *code, void **conn_cls) {
    static const char *page =
        "<html>"
            "<body>"
                "<p>Publishing to channel:</p>"
                "<form action='/publish' method='POST'>"
                    "<input type='text' name='message'/>"
                    "<input type='submit' name='submit' value='Submit'/>"
                "</form>"
            "</body>"
        "</html>";

    *code = MHD_HTTP_OK;
    return MHD_create_response_from_buffer(strlen(page), (char*)page,
            MHD_RESPMEM_PERSISTENT);
}

static void publish_post_cb(void *cls, const char *key, const char *value,
        size_t length) {
    UT_string *page = (UT_string*)cls;
    utstring_printf(page, "\t<li><b>%s:</b> %.*s</li>\n", key, length, value);
}

static struct MHD_Response* publish_post(void *cls,
        struct MHD_Connection *connection, const char *url, const char *method,
        struct MHDU_Connection *mhdu_con, int *code, void **conn_cls) {
    struct MHDU_PubSub *pubsub = (struct MHDU_PubSub*)cls;

    UT_string page;
    utstring_init(&page);

    utstring_printf(&page, "<html><body><p>POST to channel: %s</p><ul>\n");

    MHDU_attributes_iter(mhdu_con, &publish_post_cb, &page);

    const char *value;
    size_t length;
    MHDU_attribute_get(mhdu_con, "message", &value, &length);
    MHDU_ERR("Testing _get.  message: %.*s", (int)length, value);

    MHDU_LOG("Testing iterating by indexes");
    for (unsigned int i = 0; i < MHDU_attribute_count(mhdu_con); i++) {
        const char *i_key;
        const char *i_value;
        size_t i_length;
        MHDU_attribute_index(mhdu_con, i, &i_key, &i_value, &i_length);
        MHDU_ERR("%s: %.*s", i_key, (int)i_length, i_value);
    }

    utstring_printf(&page, "</ul></body></html>");

    MHDU_publish_data(pubsub, utstring_body(&page), utstring_len(&page),
            MHD_RESPMEM_MUST_COPY);

    *code = MHD_HTTP_OK;
    return MHD_create_response_from_buffer(utstring_len(&page),
            utstring_body(&page), MHD_RESPMEM_MUST_FREE);
}

static ssize_t subscribe_cb(void *cls, const char *value, size_t length,
        size_t offset, char *buf, size_t max) {
    size_t n;
    size_t left = length - offset;

    MHDU_LOG("Length: %zd, Offset: %zd, Max: %zd", length, offset, max);
    if (left > max) {
        n = max;
    } else {
        n = left;
    }
    MHDU_LOG("Copying %zd bytes", n);
    memcpy(buf, value + offset, n);
    return n;
}

static struct MHD_Response* subscribe(void *cls,
        struct MHD_Connection *connection, const char *url, const char *method,
        struct MHDU_Connection *mhdu_con, int *code, void **conn_cls) {
    struct MHDU_PubSub *pubsub = (struct MHDU_PubSub*)cls;

    return MHDU_create_response_from_subscription(pubsub, mhdu_con, code,
            &subscribe_cb, NULL, pubsub);
}

int main(int argc, char **argv) {
    /* Set up signal handler */
    struct sigaction action = {
        .sa_handler = &signal_handler,
    };
    if (sigaction(SIGINT, &action, NULL) != 0) {
        MHDU_ERR("Failed to set SIGINT signal handler");
        return 1;
    }
    if (sigaction(SIGTERM, &action, NULL) != 0) {
        MHDU_ERR("Failed to set SIGTERM signal handler");
        return 1;
    }

    struct MHDU_Router *router = NULL;
    struct MHD_Daemon *daemon = NULL;
    struct MHDU_PubSub *pubsub = NULL;

    wait_fd = eventfd(0, 0);

    if (wait_fd == -1) {
        MHDU_ERR("Failed to create eventfd.");
        return 1;
    }

    struct pollfd poll_fds[] = {{
        .fd = wait_fd,
            .events = POLLIN,
    }};

    router = MHDU_create_router();
    if (router == NULL) {
        goto done;
    }

    pubsub = MHDU_start_pubsub();
    if (pubsub == NULL) {
        goto done;
    }

    if (MHDU_add_route(router, "^/\\(.*\\)/query$", MHDU_METHOD_GET,
                &test_get1, NULL) != MHD_YES) {
        MHDU_ERR("Failed to add route.");
        goto done;
    }

    if (MHDU_add_route(router, "^/publish$", MHDU_METHOD_GET,
                &publish_get, NULL) != MHD_YES) {
        MHDU_ERR("Failed to add route.");
        goto done;
    }

    if (MHDU_add_route(router, "^/publish$", MHDU_METHOD_POST,
                &publish_post, pubsub) != MHD_YES) {
        MHDU_ERR("Failed to add route.");
        goto done;
    }

    if (MHDU_add_route(router, "^/subscribe$", MHDU_METHOD_GET,
                &subscribe, pubsub) != MHD_YES) {
        MHDU_ERR("Failed to add route.");
        goto done;
    }

    daemon = MHDU_start_daemon(
            MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG,
            DEFAULT_PORT, router);
    if (daemon == NULL) {
        goto done;
    }

    printf("Server started on port %d\n", DEFAULT_PORT);

    while (1) {
        int num_events = poll(poll_fds, 1, -1);
        if (num_events < 0 && errno != EINTR) {
            MHDU_ERR("Failed to poll");
            break;
        }
        if (poll_fds[0].revents & POLLIN) {
            uint64_t x;
            if (read(wait_fd, &x, sizeof(x)) == -1) {
                MHDU_ERR("Failed to read from event file descriptor.");
            }
            break;
        }
    }

done:
    printf("Shutting down server.");

    close(wait_fd);
    MHDU_stop_pubsub(pubsub);
    MHD_stop_daemon(daemon);
    MHDU_destroy_router(router);
    return 0;
}
