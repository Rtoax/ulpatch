// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <malloc.h>
#include <string.h>

#include <utils/log.h>
#include <utils/list.h>
#include <task/task.h>

#include <tests/test-api.h>

int nr_tests = 0;


__attribute__((nonnull(1)))
struct test *create_test(struct test *test)
{
	test->idx = ++nr_tests;
	list_add(&test->node, &test_list[test->prio - TEST_PRIO_START]);
	return test;
}

void release_tests(void)
{
	int i;
	struct test *test, *tmp;
	for (i = 0; i < TEST_PRIO_NUM; i++)
		list_for_each_entry_safe(test, tmp, &test_list[i], node)
			list_del(&test->node);
}

const char *str_special_ret(test_special_ret val)
{
	switch (val) {
	case TEST_RET_SKIP:
		return "ULPatch Skip";
		break;
	case TEST_RET_EMERG:
		return "ULPatch Emergency";
		break;
	default:
		break;
	}
	return NULL;
}
