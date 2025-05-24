// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>

#include <utils/log.h>
#include <task/fd.h>


void init_fds_root(struct fds_root *root)
{
	memset(root, 0, sizeof(struct fds_root));
	list_init(&root->list);
}

void print_fd(FILE *fp, struct fd *fd)
{
	fprintf(fp, "fd %d -> %s\n", fd->fd, fd->symlink);
}
