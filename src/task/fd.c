// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>

#include "utils/log.h"
#include "task/fd.h"
#include "task/task.h"


void init_fds_root(struct fds_root *root)
{
	memset(root, 0, sizeof(struct fds_root));
	list_init(&root->list);
}

struct fd *alloc_fd(pid_t pid, int _fd)
{
	int ret;
	struct fd *fd;
	char proc_fd[PATH_MAX];

	fd = malloc(sizeof(struct fd));
	memset(fd, 0x00, sizeof(struct fd));

	fd->fd = _fd;

	/* Read symbol link */
	sprintf(proc_fd, "/proc/%d/fd/%d", pid, _fd);
	ret = readlink(proc_fd, fd->symlink, PATH_MAX);
	if (ret < 0) {
		ulp_warning("readlink %s failed\n", proc_fd);
		strncpy(fd->symlink, "[UNKNOWN]", PATH_MAX);
		errno = -ENOENT;
		return NULL;
	}

	list_init(&fd->node);

	return fd;
}

void free_fd(struct fd *fd)
{
	list_del(&fd->node);
	free(fd);
}

static void dir_iter_callback_fd(const char *name, void *arg)
{
	struct fd *fd;
	struct task_struct *task = arg;
	int ifd = atoi(name);
	fd = alloc_fd(task->pid, ifd);
	list_add(&fd->node, &task->fds_root.list);
}

void task_load_fds(struct task_struct *task)
{
	char buf[128];
	if (!(task->fto_flag & FTO_FD))
		return;
	dir_iter(strprintbuf(buf, sizeof(buf), "/proc/%d/fd/", task->pid),
		dir_iter_callback_fd, task);
}

void print_fd(FILE *fp, struct fd *fd)
{
	fprintf(fp, "fd %d -> %s\n", fd->fd, fd->symlink);
}

void dump_task_fds(FILE *fp, struct task_struct *task, bool detail)
{
	struct fd *fd;

	if (!fp)
		fp = stdout;

	if (!(task->fto_flag & FTO_FD)) {
		ulp_error("Not set FTO_FD(%ld) flag\n", FTO_FD);
		return;
	}

	list_for_each_entry(fd, &task->fds_root.list, node)
		print_fd(fp, fd);
}
