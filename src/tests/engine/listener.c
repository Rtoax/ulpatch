// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "utils/log.h"
#include "utils/list.h"
#include "utils/compiler.h"
#include "task/task.h"
#include "elf/elf-api.h"

#include "tests/test-api.h"


static int epollfd = -1;
static int listenfd = -1;


int init_listener(void)
{
	int ret = 0;
	struct epoll_event event;
	struct sockaddr_un srv_addr;

	if (epollfd != -1) {
		ulp_warning("already initial\n");
		return -EPERM; /* Operation not permitted */
	}

	epollfd = epoll_create(1);
	assert(epollfd != -1 && "epoll_create failed.\n");

	listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listenfd < 0) {
		ret = -errno;
		ulp_error("create listening socket error, %m\n");
		return ret;
	}
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, NULL, 0);

	if (fexist(TEST_UNIX_PATH) && (ret = unlink(TEST_UNIX_PATH))) {
		ulp_error("unlink(%s) failed, %m\n", TEST_UNIX_PATH);
		goto error;
	}

	srv_addr.sun_family = AF_UNIX;
	strncpy(srv_addr.sun_path, TEST_UNIX_PATH, sizeof(srv_addr.sun_path) - 1);
	ret = bind(listenfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (ret == -1) {
		ret = -errno;
		ulp_error("cannot bind server socket, %m\n");
		goto error;
	}
	ret = listen(listenfd, 1);

	event.events = EPOLLIN;
	event.data.fd = listenfd;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &event);
	if (ret == -1) {
		ret = -errno;
		ulp_error("cannot add listendfd to epoll, %m\n");
		goto error;
	}

	return 0;

error:
	close(epollfd);
	close(listenfd);
	unlink(TEST_UNIX_PATH);
	return ret;
}

void close_listener(void)
{
	close(epollfd);
	close(listenfd);
	unlink(TEST_UNIX_PATH);
}

int listener_helper_create_test_client(void)
{
	int connect_fd, ret = -1;
	struct sockaddr_un srv_addr;

	connect_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (connect_fd < 0) {
		ulp_error("create socket error: %m\n");
		return -EINVAL;
	}

	srv_addr.sun_family = AF_UNIX;
	strcpy(srv_addr.sun_path, TEST_UNIX_PATH);

	ret = connect(connect_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (ret == -1) {
		ulp_error("connect error: %m, %s\n", TEST_UNIX_PATH);
		close(connect_fd);
		exit(1);
	}
	return connect_fd;
}

int listener_helper_close_test_client(int fd)
{
	return close(fd);
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

static void handle_msg_symbol(struct test_client *client, struct ctrl_msg *msg)
{
	int ret;
	struct ctrl_msg ack;
	const char *s = msg->body.symbol_request.s;
	struct test_symbol *sym = find_test_symbol(s);

	ack.hdr.type = TEST_MT_RESPONSE;
	ack.hdr.code = TEST_MC_SYMBOL;
	ack.body.symbol_response.addr = sym ? sym->addr : 0;

	ret = write(client->connfd, &ack, sizeof(ack));
	if (ret != sizeof(ack)) {
		ulp_error("write(2): %m\n");
	}
}

int listener_helper_close(int fd, int *rslt)
{
	int ret;
	struct ctrl_msg req, rsp;

	req.hdr.type = TEST_MT_REQUEST;
	req.hdr.code = TEST_MC_CLOSE;

	ret = write(fd, &req, sizeof(req));
	if (ret != sizeof(req)) {
		ulp_error("write(2): %m\n");
	}
	ret = read(fd, &rsp, sizeof(rsp));
	if (ret != sizeof(rsp)) {
		ulp_error("read(2): %m\n");
	}

	*rslt = rsp.body.close_response.rslt;

	return 0;
}

int listener_helper_symbol(int fd, const char *sym, unsigned long *addr)
{
	int ret;
	struct ctrl_msg req, rsp;

	req.hdr.type = TEST_MT_REQUEST;
	req.hdr.code = TEST_MC_SYMBOL;

	strncpy(req.body.symbol_request.s, sym,
		sizeof(req.body.symbol_request.s) - 1);

	ret = write(fd, &req, sizeof(req));
	if (ret != sizeof(req)) {
		ulp_error("write(2): %m\n");
	}
	ret = read(fd, &rsp, sizeof(rsp));
	if (ret != sizeof(rsp)) {
		ulp_error("read(2): %m\n");
	}

	*addr = rsp.body.symbol_response.addr;

	return 0;
}


static bool listener_need_close = false;

static void recv_test_client_msg(struct test_client *client)
{
	int ret;
	size_t nbytes;
	struct ctrl_msg msg, ack;

	nbytes = read(client->connfd, &msg, sizeof(msg));
	if (nbytes <= 0) {
		ulp_error("read(2): %m\n");
		return;
	}

	if (msg.hdr.type != TEST_MT_REQUEST) {
		ulp_error("Read unknown msg type %d\n", msg.hdr.type);
		return;
	}

	switch (msg.hdr.code) {

	case TEST_MC_SYMBOL:
		handle_msg_symbol(client, &msg);
		break;

	case TEST_MC_CLOSE:
		listener_need_close = true;

		ack.hdr.type = TEST_MT_RESPONSE;
		ack.hdr.code = TEST_MC_CLOSE;
		ack.body.close_response.rslt = 0;

		ret = write(client->connfd, &ack, sizeof(ack));
		if (ret != sizeof(ack)) {
			ulp_error("write(2): %m\n");
		}

		break;

	default:
		ulp_error("unknown msg code %d\n", msg.hdr.code);
		break;
	}
}

void listener_main_loop(void *arg)
{
	int i, ret, nfds;
	struct epoll_event events[MAX_EVENTS];

	for (;;) {

		/* check should exit or not */
		if (listener_need_close) {
			goto out;
		}

		nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		if (nfds == -1) {
			ulp_error("epoll_wait: %m\n");
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
					ulp_error("cannot add fd to epoll, %m\n");
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

							/* Only handle one client, then exit */
							if (test_nr_clients == 0) {
								goto out;
							}

						/* Handle a client */
						} else if (event->events & EPOLLIN) {
							recv_test_client_msg(client);
						}
					}
				}
			}
		}
	}

out:
	close_listener();
	return;
}
