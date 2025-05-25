// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <assert.h>
#include <malloc.h>
#include <string.h>

#include "utils/log.h"
#include "utils/list.h"
#include "task/task.h"

#include "tests/test-api.h"

int nr_tests = 0;

struct list_head test_list;

void init_tests(void)
{
	struct test *t, *end, *start;
	size_t size;

	list_init(&test_list);

	t = &__test_meta_start;

	while (t && t < &__test_meta_end) {
		create_test(t);
		/**
		 * FIXME: WTF? why need +8?????????????????
		 */
		t = (void *)((unsigned long)t + sizeof(struct test) + 8);
	}

	start = &__test_meta_start;
	end = &__test_meta_end;

	size = (unsigned long)end - (unsigned long)start;

	ulp_debug("Total tests size %ld\n", size);

	assert((size % sizeof(struct test)));
}

__attribute__((nonnull(1)))
struct test *create_test(struct test *test)
{
	test->idx = ++nr_tests;
	list_add(&test->node, &test_list);
	return test;
}

void release_tests(void)
{
	struct test *test, *tmp;
	list_for_each_entry_safe(test, tmp, &test_list, node)
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
