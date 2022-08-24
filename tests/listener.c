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


static int __unused init_listener(void)
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

static void __unused close_listener(void)
{
	close(epollfd);
	close(listenfd);
	unlink(TEST_UNIX_PATH);
}

