#include <malloc.h>
#include <string.h>

#include "test_api.h"

struct test*
create_test(char *category, char *name, test_prio prio, int (*cb)(void),
	int expect_ret)
{
	struct test *test = malloc(sizeof(struct test));
	test->category = strdup(category);
	test->name = strdup(name);
	test->prio = prio;
	test->test_cb = cb;
	test->expect_ret = expect_ret;

	list_add(&test->node, &test_list[prio - TEST_PRIO_START]);

	return test;
}
