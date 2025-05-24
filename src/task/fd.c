// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>

#include <utils/log.h>
#include <task/fd.h>

void print_fd(FILE *fp, struct fd *fd)
{
	fprintf(fp, "fd %d -> %s\n", fd->fd, fd->symlink);
}
