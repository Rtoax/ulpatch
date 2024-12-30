// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <malloc.h>
#include <string.h>

#include <utils/log.h>
#include <utils/list.h>
#include <task/task.h>

#include <tests/test-api.h>

int nr_tests = 0;


__attribute__((nonnull(1, 2, 4)))
struct test *create_test(char *category, char *name, test_prio prio,
			 int (*cb)(void), int expect_ret)
{
	struct test *test;
	const char *err = "Success";

	if (strlen(category) == 0) {
		err = "Wrong category";
		goto invalid;
	}

	if (strlen(name) == 0) {
		err = "Wrong name";
		goto invalid;
	}

	if (prio < TEST_PRIO_HIGHEST || prio > TEST_PRIO_LOWER) {
		err = "Wrong prio";
		goto invalid;
	}

	test = malloc(sizeof(struct test));

	test->idx = ++nr_tests;
	test->category = strdup(category);
	test->name = strdup(name);
	test->prio = prio;
	test->test_cb = cb;
	test->expect_ret = expect_ret;
	test->real_ret = expect_ret;

	list_add(&test->node, &test_list[prio - TEST_PRIO_START]);

	return test;

invalid:
	fprintf(stderr, "ERROR: fatal add test: %s.%s %s\n", category, name,
		err);
	abort();
	return NULL;
}

void release_tests(void)
{
	int i;
	struct test *test, *tmp;

	/* for each priority */
	for (i = 0; i < TEST_PRIO_NUM; i++) {
		/* for each test entry */
		list_for_each_entry_safe(test, tmp, &test_list[i], node) {
			list_del(&test->node);
			free(test->category);
			free(test->name);
			free(test);
		}
	}
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

TEST(test, SIGILL, TEST_RET_SKIP)
{
	INIT_TEST_JMP();
	/* Trigger SIGILL */
	__asm__ __volatile__("ud2\n");
	return 0;
}
