// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025 Rong Tao */
#include <malloc.h>
#include <string.h>

#include <utils/log.h>
#include <utils/list.h>
#include <task/task.h>

#include <tests/test-api.h>

TEST_STUB(test_signal);

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
#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Warray-bounds"
//# pragma clang diagnostic ignored "-Wstringop-overflow"
#elif defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Warray-bounds"
# if __GNUC__ >= 11 && __GNUC_MINOR__ >= 1
#  pragma GCC diagnostic ignored "-Wstringop-overflow"
# endif
#endif
	str[1024] = 'a';
#if defined(__clang__)
# pragma clang diagnostic pop
#elif defined(__GNUC__)
# pragma GCC diagnostic pop
#endif
	return 0;
}
