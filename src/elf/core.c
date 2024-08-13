// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>


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
	if (!default_libc_object) {
		lerror("Could not found libc.so in possible_libc.\n");
		exit(1);
		/* FIXME: Use getenv() */
	}

	return 0;
}

const char *libc_object(void)
{
	return default_libc_object;
}
