// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 CESTC, Co. Rong Tao <rongtao@cestc.cn> */
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
#include <utils/compiler.h>

#include "patch.h"


const static char *___ftrace_entry_funcs[] = {
    "__cyg_profile_func_enter",
    "__fentry__",
    "mcount",
    "_mcount",
    "__gnu_mcount_nc",
};

/* If compile with -pg, there might be hava mcount() */
bool is_ftrace_entry(char *func)
{
	int i;
	bool ret = false;

	for (i = 0; i < ARRAY_SIZE(___ftrace_entry_funcs); i++) {
		if (!strcmp(___ftrace_entry_funcs[i], func)) {
			ret = true;
			break;
		}
	}

	return ret;
}

