// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
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

int listener_helper_create_test_client(void)
{
	int connect_fd, ret = -1;
	struct sockaddr_un srv_addr;

	connect_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (connect_fd < 0) {
		lerror("create socket error: %s\n", strerror(errno));
		return -EINVAL;
	}

	srv_addr.sun_family = AF_UNIX;
	strcpy(srv_addr.sun_path, TEST_UNIX_PATH);

	ret = connect(connect_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (ret == -1) {
		lerror("connect error: %s, %s\n", strerror(errno), TEST_UNIX_PATH);
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

static void handle_msg_symbol(struct test_client *client, struct clt_msg *msg)
{
	struct clt_msg ack;
	const char *s = msg->body.symbol_request.s;
	struct test_symbol *sym = find_test_symbol(s);

	ack.hdr.type = TEST_MT_RESPONSE;
	ack.hdr.code = TEST_MC_SYMBOL;
	ack.body.symbol_response.addr = sym ? sym->addr : 0;

	write(client->connfd, &ack, sizeof(ack));
}

int listener_helper_close(int fd, int *rslt)
{
	struct clt_msg req, rsp;

	req.hdr.type = TEST_MT_REQUEST;
	req.hdr.code = TEST_MC_CLOSE;

	write(fd, &req, sizeof(req));
	read(fd, &rsp, sizeof(rsp));

	*rslt = rsp.body.close_response.rslt;

	return 0;
}

int listener_helper_symbol(int fd, const char *sym, unsigned long *addr)
{
	struct clt_msg req, rsp;

	req.hdr.type = TEST_MT_REQUEST;
	req.hdr.code = TEST_MC_SYMBOL;

	strncpy(req.body.symbol_request.s, sym,
		sizeof(req.body.symbol_request.s) - 1);

	write(fd, &req, sizeof(req));
	read(fd, &rsp, sizeof(rsp));

	*addr = rsp.body.symbol_response.addr;

	return 0;
}


static bool listener_need_close = false;

static void recv_test_client_msg(struct test_client *client)
{
	size_t nbytes;
	struct clt_msg msg, ack;

	nbytes = read(client->connfd, &msg, sizeof(msg));
	if (nbytes <= 0) {
		lerror("read(2): %s\n", strerror(errno));
		return;
	}

	if (msg.hdr.type != TEST_MT_REQUEST) {
		lerror("Read unknown msg type %d\n", msg.hdr.type);
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

		write(client->connfd, &ack, sizeof(ack));

		break;

	default:
		lerror("unknown msg code %d\n", msg.hdr.code);
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

