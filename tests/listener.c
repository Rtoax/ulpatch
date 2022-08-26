// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/epoll.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>
#include <utils/task.h>
#include <elf/elf_api.h>

#include "test_api.h"


static int epollfd = -1;
static int listenfd = -1;


int init_listener(void)
{
	int ret = 0;
	struct epoll_event event;
	struct sockaddr_un srv_addr;

	if (epollfd != -1) {
		lwarning("already initial\n");
		return -EPERM; /* Operation not permitted */
	}

	epollfd = epoll_create(1);
	assert(epollfd != -1 && "epoll_create failed.\n");

	/* Create unix domain socket */
	listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listenfd < 0) {
		ret = -errno;
		lerror("create listening socket error, %s\n", strerror(errno));
		return ret;
	}
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, NULL, 0);

	if (fexist(TEST_UNIX_PATH) && (ret = unlink(TEST_UNIX_PATH))) {
		lerror("unlink(%s) failed, %s\n", TEST_UNIX_PATH, strerror(errno));
		close(epollfd);
		close(listenfd);
		return -errno;
	}

	srv_addr.sun_family = AF_UNIX;
	strncpy(srv_addr.sun_path, TEST_UNIX_PATH, sizeof(srv_addr.sun_path) - 1);
	ret = bind(listenfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (ret == -1) {
		ret = -errno;
		lerror("cannot bind server socket, %s\n", strerror(errno));
		close(epollfd);
		close(listenfd);
		unlink(TEST_UNIX_PATH);
		return ret;
	}
	ret = listen(listenfd, 1);

	event.events = EPOLLIN;
	event.data.fd = listenfd;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &event);
	if (ret == -1) {
		ret = -errno;
		lerror("cannot add listendfd to epoll, %s\n", strerror(errno));
		close(epollfd);
		close(listenfd);
		unlink(TEST_UNIX_PATH);
		return ret;
	}

	return 0;
}

void close_listener(void)
{
	close(epollfd);
	close(listenfd);
	unlink(TEST_UNIX_PATH);
}

#define MAX_EVENTS	64

struct test_client {
	int connfd;

	struct sockaddr_un addr;
	/* client list node */
	struct list_head node;
};

/* client list head */
static LIST_HEAD(test_client_list);
static unsigned int test_nr_clients = 0;

void handle_test_client_msg(struct test_client *client)
{
	// TODO
}

void listener_main_loop(void *arg)
{
	int i, ret, nfds;
	struct epoll_event events[MAX_EVENTS];

	for (;;) {
		nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		if (nfds == -1) {
			lerror("epoll_wait: %s\n", strerror(errno));
			continue;
		}
		for (i = 0; i < nfds; i++) {
			struct epoll_event *event = &events[i];

			/* Add a new client */
			if (event->data.fd == listenfd) {
				struct epoll_event event;
				socklen_t len = sizeof(struct sockaddr_un);
				struct test_client *client = malloc(sizeof(struct test_client));

				memset(client, 0x0, sizeof(struct test_client));

				client->connfd = accept(listenfd,
					(struct sockaddr*)&client->addr, &len);

				/* Add new client to epoll */
				event.events = EPOLLIN;
				event.data.fd = client->connfd;

				ret = epoll_ctl(epollfd, EPOLL_CTL_ADD,
							client->connfd, &event);
				if (ret == -1) {
					lerror("cannot add fd to epoll, %s\n", strerror(errno));
					free(client);
					continue;
				}
				list_add(&client->node, &test_client_list);
				test_nr_clients++;

			/* Handle all client */
			} else {
				struct test_client *client, *tmp;

				list_for_each_entry_safe(client, tmp, &test_client_list, node) {
					if (client->connfd == event->data.fd) {
						/* Client close */
						if (event->events & EPOLLHUP) {
							close(client->connfd);

							epoll_ctl(epollfd, EPOLL_CTL_DEL,
								client->connfd, NULL);

							list_del(&client->node);
							free(client);
							test_nr_clients--;

						/* Handle a client */
						} else if (event->events & EPOLLIN) {
							handle_test_client_msg(client);
						}
					}
				}
			}
		}
	}
}

