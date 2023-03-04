// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao */
#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <elf/elf_api.h>
#include <patch/patch.h>

#include "../test_api.h"


/* see: root CMakeLists.txt */
static const char *upatch_objs[] = {
	/* /usr/share/upatch/ftrace-mcount.obj */
	UPATCH_FTRACE_OBJ_PATH,
	/* /usr/share/upatch/upatch-hello.obj */
	UPATCH_HELLO_OBJ_PATH,
};


TEST(Object,	check_objs_exist,	0)
{
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(upatch_objs); i++) {
		if (!fexist(upatch_objs[i])) {
			ret = -EEXIST;
			fprintf(stderr, "\n%s is not exist, maybe: make install\n",
				upatch_objs[i]);
		}
	}

	return ret;
}


