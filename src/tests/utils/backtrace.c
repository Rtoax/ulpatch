// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <sys/types.h>
#include <unistd.h>
#include <utils/log.h>
#include <utils/util.h>
#include <tests/test-api.h>

TEST_STUB(utils_backtrace);

static void bar(void)
{
	do_backtrace(stdout);
}

static void foo(void)
{
	bar();
}

TEST(Utils_backtrace, base, 0)
{
	foo();
	return 0;
}

