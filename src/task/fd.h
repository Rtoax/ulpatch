// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once
#include <limits.h>
#include <sys/types.h>

#include <utils/list.h>

/**
 * Record all file descriptors of target task
 *
 * @fd - read from /proc/PID/fd/
 */
struct fd {
	int fd;
	/* Like /proc/self/fd/0 -> /dev/pts/3 */
	char symlink[PATH_MAX];
	/* struct task_struct.fds_list */
	struct list_head node;
};

void print_fd(FILE *fp, struct fd *fd);
