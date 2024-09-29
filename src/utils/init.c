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
#include <task/task.h>
#include <utils/log.h>
#include <utils/compiler.h>

#include <patch/patch.h>
#include <patch/meta.h>


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
	 * The struct ulpatch_info.orig_code MUST store the original code.
	 */
	if (sizeof(struct jmp_table_entry) > \
	    sizeof(((struct ulpatch_info *)0)->orig_code)) {
		ulp_error("ulpatch_info::orig_code overflow.\n");
		goto error;
	}
	/* MORE */

	return;
error:
	exit(1);
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

extern void init_syslog(void);

void ulpatch_init(void)
{
	reset_current_task();

	init_syslog();

	__check_and_exit();
	__env_init();

	elf_core_init();
}

/* Dry run APIs */
bool is_dry_run(void)
{
	return __dry_run;
}

void enable_dry_run(void)
{
	__dry_run = true;
}

/* Verbose APIs */
bool is_verbose(void)
{
	return !!__verbose;
}

int get_verbose(void)
{
	return __verbose;
}

int str2verbose(const char *str)
{
	int v, i;

	if (!str || strlen(str) == 0)
		return 0;

	v = 0;
	for (i = 0; i < strlen(str); i++) {
		if (str[i] == 'v')
			v++;
	}
	return v;
}

void enable_verbose(int verbose)
{
	__verbose = verbose;
}

void reset_verbose(void)
{
	enable_verbose(0);
}
