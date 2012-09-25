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
#include "microhttpd_utils.h"

static const uint16_t DEFAULT_PORT = 6892;

static int wait_fd;

static void signal_handler(int signal) {
    static const uint64_t x = 1;
    if (write(wait_fd, &x, sizeof(x)) == -1) {
        MHDU_ERR("Failed to write to event file descriptor.");
    }
}

static struct MHD_Response* handler1(void *cls,
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

static struct MHD_Response* handler2(void *cls,
        struct MHD_Connection *connection, const char *url, const char *method,
        struct MHDU_Connection *mhdu_con, int *code, void **conn_cls) {
    static const char *page =
        "<html>"
            "<body>"
                "<form action='/publish' method='POST'>"
                    "<input type='text' name='foo'/>"
                    "<input type='submit' name='submit' value='Submit'/>"
                "</form>"
            "</body>"
        "</html>";

    *code = MHD_HTTP_OK;
    return MHD_create_response_from_buffer(strlen(page), (char*)page,
            MHD_RESPMEM_PERSISTENT);
}

static void handler3_cb(void *cls, const char *key, const char *value,
                        size_t length) {
    UT_string *page = (UT_string*)cls;
    utstring_printf(page, "\t<li><b>%s:</b> %.*s</li>\n", key, length, value);
}

static struct MHD_Response* handler3(void *cls,
        struct MHD_Connection *connection, const char *url, const char *method,
        struct MHDU_Connection *mhdu_con, int *code, void **conn_cls) {
    struct MHDU_PubSubManager *pubsub = (struct MHDU_PubSubManager*)cls;

    UT_string page;
    utstring_init(&page);

    utstring_printf(&page, "<html><body><p>POST:</p><ul>\n");

    MHDU_attributes_iter(mhdu_con, &handler3_cb, &page);

    utstring_printf(&page, "</ul></body></html>");

    MHDU_publish_data(pubsub, "sub1", utstring_body(&page),
                     utstring_len(&page));

    *code = MHD_HTTP_OK;
    return MHD_create_response_from_buffer(utstring_len(&page),
            utstring_body(&page), MHD_RESPMEM_MUST_FREE);
}

static ssize_t handler4_cb(void *cls, const char *channel, const char *value,
                           size_t length, char *buf, size_t max) {
    MHDU_LOG("FOOOOO");
    size_t n;
    if (length > max) {
        n = max;
    } else {
        n = length;
    }
    memcpy(buf, value, n);
    return n;
}

static struct MHD_Response* handler4(void *cls,
        struct MHD_Connection *connection, const char *url, const char *method,
        struct MHDU_Connection *mhdu_con, int *code, void **conn_cls) {

    struct MHDU_PubSubManager *pubsub = (struct MHDU_PubSubManager*)cls;

    return MHDU_create_response_from_subscription(pubsub, mhdu_con, "sub1",
            code, &handler4_cb, pubsub);
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
    struct MHDU_PubSubManager *pubsub = NULL;

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

    pubsub = MHDU_create_pubsub_manager();
    if (pubsub == NULL) {
        goto done;
    }

    if (MHDU_add_route(router, "^/\\(.*\\)/query$", MHDU_METHOD_GET, &handler1,
                       NULL) != MHD_YES) {
        MHDU_ERR("Failed to add route.");
        goto done;
    }

    if (MHDU_add_route(router, "^/publish$", MHDU_METHOD_GET, &handler2,
                       NULL) != MHD_YES) {
        MHDU_ERR("Failed to add route.");
        goto done;
    }

    if (MHDU_add_route(router, "^/publish$", MHDU_METHOD_POST, &handler3,
                       pubsub) != MHD_YES) {
        MHDU_ERR("Failed to add route.");
        goto done;
    }

    if (MHDU_add_route(router, "^/subscribe$", MHDU_METHOD_GET, &handler4,
                       pubsub) != MHD_YES) {
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
            break;
        }
    }

done:
    printf("Shutting down server.");

    close(wait_fd);
    MHD_stop_daemon(daemon);
    MHDU_destroy_pubsub_manager(pubsub);
    MHDU_destroy_router(router);
    return 0;
}
