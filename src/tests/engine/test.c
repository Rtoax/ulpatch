// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
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
	struct test *t;
	size_t test_lds_size, i;
	void *p;

	list_init(&test_list);

	/**
	 * Because the alignment method of struct test is preserved in lds,
	 * test operations cannot be used directly. Here, we first obtain the
	 * size of test in the ELF section according to a specific alignment
	 * method. Of course, this is done by comparing magic numbers.
	 */
	p = (void *)&__test_meta_start;
	for (test_lds_size = 1; ; test_lds_size++) {
		if (*(unsigned long *)(p + test_lds_size) == TEST_MAGIC)
			break;
	}

	p = (void *)&__test_meta_start;
	t = p;
	i = 0;
	while (t && t < &__test_meta_end) {
		create_test(t);
		/* NOTE: don't use t++ here. */
		t = (p + test_lds_size * (++i));
	}
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
