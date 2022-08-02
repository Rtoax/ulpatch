#include <utils/log.h>
#include <utils/list.h>
#include <elf/elf_api.h>

#include "../test_api.h"


struct test_data {
	int v;
	struct list_head node;
};


TEST(List,	list,	0)
{
	LIST_HEAD(list1);
	int i;
	struct test_data *tmp = NULL;

	struct test_data tests[] = {
		{0,}, {1,}, {2,}, {3,}, {4,},
		{6,}, {7,}, {8,}, {9,}, {10,},
	};

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		tmp = &tests[i];
		list_add(&tmp->node, &list1);
	}

	list_for_each_entry(tmp, &list1, node) {
		ldebug("%d\n", tmp->v);
	}

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		tmp = &tests[i];
		list_del(&tmp->node);
	}

	return 0;
}

