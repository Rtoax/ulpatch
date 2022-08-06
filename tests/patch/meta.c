// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <elf/elf_api.h>
#include <patch/patch.h>

#include "../test_api.h"

static __unused int patch_me(void)
{
	return 0;
}

int i_am_a_patch(void)
{
	return 1;
}

UPATCH_INFO(patch_me, i_am_a_patch, "Rong Tao");

TEST(Patch_meta,	macro__UPATCH_INFO,	0)
{
	return 0;
}

