// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <elf/elf_api.h>
#include <patch/patch.h>

#include <tests/test_api.h>

/**
 * This is target function to patch, the patch object see
 * src/patch/objects/hello/
 */
void hello_world(void)
{
	printf("Hello Wrold from original.\n");
}


TEST(ULPatch,	object_hello,	0)
{
	/* original */
	hello_world();

	/* TODO: apply patch */

	/* patched */
	hello_world();

	/* TODO: unapply patch */

	/* unpatched */
	hello_world();

	fprintf(stderr, "WARN: todo.\n");
	return 0;
}

