// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#include <errno.h>

#include "utils/log.h"
#include "utils/list.h"
#include "utils/utils.h"
#include "task/task.h"
#include "elf/elf-api.h"
#include "patch/patch.h"

#include "tests/test-api.h"

/* see: root CMakeLists.txt */
const struct ulpatch_object ulpatch_objs[] = {
	{
		.type = ULPATCH_OBJ_TYPE_FTRACE,
		.path = ULPATCH_OBJ_FTRACE_MCOUNT_PATH
	},
	{
		.type = ULPATCH_OBJ_TYPE_ULP,
		.path = ULPATCH_TEST_ULP_EMPTY_PATH
	},
	{
		.type = ULPATCH_OBJ_TYPE_ULP,
		.path = ULPATCH_TEST_ULP_PRINTF_PATH
	},
};

int nr_ulpatch_objs(void)
{
	return ARRAY_SIZE(ulpatch_objs);
}
