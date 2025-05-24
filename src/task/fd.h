// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once
#include <limits.h>
#include <sys/types.h>

#include <utils/list.h>

struct task_struct;

/* Record one file descriptors of target task */
struct fd {
	/* @fd - read from /proc/PID/fd/ */
	int fd;
	/* Like /proc/self/fd/0 -> /dev/pts/3 */
	char symlink[PATH_MAX];
	/* struct fds_root.list */
	struct list_head node;
};

struct fds_root {
	/* struct fd.node */
	struct list_head list;
};

void init_fds_root(struct fds_root *root);

struct fd *alloc_fd(pid_t pid, int _fd);
void free_fd(struct fd *fd);

void dump_task_fds(FILE *fp, struct task_struct *task, bool detail);
void print_fd(FILE *fp, struct fd *fd);
