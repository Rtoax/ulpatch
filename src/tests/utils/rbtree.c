// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <utils/log.h>
#include <utils/rbtree.h>
#include <elf/elf_api.h>

#include "../test_api.h"


struct test_data {
	int v;
	struct rb_node node;
};


static int cmp_data(struct rb_node *n1, unsigned long key) {
	struct test_data *s1 = rb_entry(n1, struct test_data, node);
	int v = (int)key;
	return s1->v - v;
}

static __unused struct test_data *find_data(struct rb_root *tree, int v)
{
	struct rb_node *node = rb_search_node(tree,
						cmp_data, (unsigned long)v);

	return node?rb_entry(node, struct test_data, node):NULL;
}

static __unused int link_data(struct rb_root *tree, struct test_data *data)
{
	struct rb_node *node = rb_insert_node(tree, &data->node,
						cmp_data, (unsigned long)data->v);
	return node?0:-1;
}

static void free_data(struct rb_node *node)
{
	struct test_data __unused *s = rb_entry(node, struct test_data, node);
	// maybe more
}

TEST(Rbtree,	rbtree,	0)
{
	int ret = -1;
	int i;
	int sum = 0;
	struct rb_root rb_tree;
	struct rb_node *node;

	struct test_data *t = NULL, *tmp;

	struct test_data tests[] = {
		{0,}, {1,}, {2,}, {3,}, {4,},
		{6,}, {7,}, {8,}, {9,}, {10,},
	};

	rb_init(&rb_tree);

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		t = &tests[i];
		link_data(&rb_tree, t);
	}

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (!find_data(&rb_tree, tests[i].v)) {
			lerror("Fail find.\n");
			sum = 1000;
		}
	}

	for (node = rb_first(&rb_tree); node; node = rb_next(node)) {
		t = rb_entry(node, struct test_data, node);
		ldebug("value: %d\n", t->v);
		sum += t->v;
	}

	for (node = rb_last(&rb_tree); node; node = rb_prev(node)) {
		t = rb_entry(node, struct test_data, node);
		ldebug("value: %d\n", t->v);
		sum -= t->v;
	}

	rbtree_postorder_for_each_entry_safe(t, tmp, &rb_tree, node) {
		ldebug("value: %d\n", t->v);

		sum += t->v;
	}

	rb_destroy(&rb_tree, free_data);

	if (sum == 50)
		ret = 0;

	return ret;
}

