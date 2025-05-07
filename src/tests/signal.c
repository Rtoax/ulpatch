// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025 Rong Tao */
#include <malloc.h>
#include <string.h>

#include <utils/log.h>
#include <utils/list.h>
#include <task/task.h>

#include <tests/test-api.h>


TEST(Signal, SIGILL, TEST_RET_SKIP)
{
	/* Trigger SIGILL */
#if defined(__x86_64__)
	__asm__ __volatile__("ud2\n");
#elif defined(__aarch64__)
	__asm__ __volatile__("udf #0\n");
#else
# error "Not support architecture!"
#endif
	return 0;
}

TEST(Signal, SIGSEGV, TEST_RET_SKIP)
{
	/* Trigger SIGSEGV */
	char *str = NULL;
	str[0] = 'a';
	return 0;
}
