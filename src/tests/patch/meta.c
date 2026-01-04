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


static __unused int patch_me(void)
{
	return 0;
}

int i_am_a_patch(void)
{
	return 1;
}

ULPATCH_INFO(patch_me, i_am_a_patch);
ULPATCH_AUTHOR("Rong Tao");
ULPATCH_LICENSE("GPL-2.0");

TEST(Patch_meta, macro__ULPATCH_INFO, 0)
{
	return 0;
}
