// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>

#include <elf/elf-api.h>
#include <utils/util.h>
#include <utils/log.h>
#include <utils/compiler.h>


static int __dry_run = false;
static int __verbose = 0;

static int __page_size = 0;
static int __page_shift = 0;

int ulp_page_size(void)
{
	if (unlikely(__page_size == 0))
		__page_size = getpagesize();
	return __page_size;
}

int ulp_page_shift(void)
{
	int tmp, pgsz = ulp_page_size();

	if (unlikely(__page_shift == 0)) {
		for (tmp = 0; (0x1UL << tmp) != pgsz; tmp++);
		__page_shift = tmp;
	}
	return __page_shift;
}

static void __check_and_exit(void)
{
	/**
	 * TODO
	 * 1. check architecture
	 */
}

static void __env_init(void)
{
	int ret;

	if (!fexist("/tmp")) {
		fprintf(stderr, "Need /tmp/\n");
		exit(1);
	}

	/**
	 * The target task could be belongs to any USER(uid), the target task
	 * will rwx ULP_PROC_ROOT_DIR, thus, give 0777 permission.
	 */
	if (!fexist(ULP_PROC_ROOT_DIR)) {
		ret = mkdirat(0, ULP_PROC_ROOT_DIR, MODE_0777);
		if (ret != 0) {
			ulp_error("Create %s failed, %m\n", ULP_PROC_ROOT_DIR);
			exit(1);
		}
	} else {
		ret = chmod(ULP_PROC_ROOT_DIR, MODE_0777);
		if (ret != 0) {
			ulp_error("Chmod %s failed, %m\n", ULP_PROC_ROOT_DIR);
			ulp_error("You could remove %s and run again.\n",
				ULP_PROC_ROOT_DIR);
			exit(1);
		}
	}
}

void ulpatch_init(void)
{
	__check_and_exit();
	__env_init();

	elf_core_init();
}

bool is_dry_run(void)
{
	return __dry_run;
}

void enable_dry_run(void)
{
	__dry_run = true;
}

bool is_verbose(void)
{
	return __verbose;
}

void enable_verbose(void)
{
	__verbose = true;
}
