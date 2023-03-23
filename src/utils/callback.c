// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 CESTC, Co. Rong Tao <rongtao@cestc.cn> */
#include <errno.h>
#include <malloc.h>
#include <utils/list.h>
#include <utils/compiler.h>


struct callback {
	void *cb_arg;
	int (*cb)(void *arg);

	/* head is struct list_head */
	struct list_head node;
};


int insert_callback(struct callback_chain *chain,
		int (*cb)(void *arg), void *cb_arg)
{
	if (!chain || !cb)
		return -ENOENT;

	struct callback *new = malloc(sizeof(struct callback));
	if (!new)
		return -ENOMEM;

	new->cb = cb;
	new->cb_arg = cb_arg;

	list_add(&new->node, &chain->head);

	return 0;
}

void callback_launch_chain(struct callback_chain *chain)
{
	struct callback *cb, *tmp;

	list_for_each_entry_safe(cb, tmp, &chain->head, node) {
		cb->cb(cb->cb_arg);
	}
}

int destroy_callback_chain(struct callback_chain *chain)
{
	struct callback *cb, *tmp;

	list_for_each_entry_safe(cb, tmp, &chain->head, node) {
		list_del(&cb->node);
		free(cb);
	}

	return 0;
}

