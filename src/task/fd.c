// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>

#include <utils/log.h>
#include <task/fd.h>
#include <task/task.h>


void init_fds_root(struct fds_root *root)
{
	memset(root, 0, sizeof(struct fds_root));
	list_init(&root->list);
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
