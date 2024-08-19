// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <sys/types.h>
#include <unistd.h>
#include <utils/log.h>
#include <utils/util.h>
#include <tests/test_api.h>


static void bar(void)
{
	do_backtrace(stdout);
}

static void foo(void)
{
	bar();
}

TEST(Backtrace, base, 0)
{
	foo();
	return 0;
}

