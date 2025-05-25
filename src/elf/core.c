// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>

#include "elf/elf-api.h"
#include "utils/utils.h"
#include "utils/log.h"


static const char *possible_libc[] = {
	"/usr/lib64/libc.so.6",
	"/lib64/libc.so.6",
	/* Ubuntu */
#if defined(__x86_64__)
	"/lib/x86_64-linux-gnu/libc.so.6",
#elif defined(__aarch64__)
	"/lib/aarch64-linux-gnu/libc.so.6",
#endif
	/* On sw_64 */
	"/lib/libc.so.6.1",
};


/**
 * If execution was compiled static, libc object should be NULL. This pointer
 * only store the libc that exist in file system, not in target task's mappings.
 */
static const char *default_libc_object = NULL;


int elf_core_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(possible_libc); i++) {
		if (fexist(possible_libc[i])) {
			default_libc_object = possible_libc[i];
			break;
		}
	}
	/**
	 * ULPatch only works on GNU/Linux, thus, LIBC is needed. You Could
	 * check /usr/include/gnu/lib-names.h header to check libc name.
	 *
	 * FIXME: We could get libc path by getenv(), maybe LIBC=SKIP to skip
	 * if not exist.
	 */
	if (!default_libc_object) {
		ulp_error("Could not found libc.so in possible_libc.\n");
		exit(1);
	}

	return 0;
}

const char *libc_object(void)
{
	return default_libc_object;
}
