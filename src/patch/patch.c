// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/task.h>
#include <utils/compiler.h>

#include "patch.h"

// see linux:kernel/module.c
static int parse_load_info(const char *obj_file, struct load_info *info)
{
	// TODO:

	return 0;
}

int init_patch(struct task *task, const char *obj_file)
{
	int err;
	struct load_info info = {};

	err = parse_load_info(obj_file, &info);
	if (err)
		return err;

	// TODO:

	return 0;
}

