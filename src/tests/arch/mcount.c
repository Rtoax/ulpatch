// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <errno.h>
#include <unistd.h>

#include <utils/log.h>
#include <utils/list.h>
#include <task/task.h>
#include <tests/test-api.h>

TEST_STUB(arch_mcount);

TEST(Arch, mcount, 0)
{
	return 0;
}

