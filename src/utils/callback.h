// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#pragma once

#include <assert.h>
#include "list.h"
#include "compiler.h"

struct callback {
	void *cb_arg;
	int (*cb)(void *arg);

	// head is struct list_head
	struct list_head node;
};


#define INIT_CB_CHAIN(name)	LIST_HEAD(name)


static __unused int insert_callback(struct list_head *chain,
	int (*cb)(void *arg), void *cb_arg)
{
	assert(cb && "callback is NULL");

	struct callback *new = malloc(sizeof(struct callback));
	assert(new && "Malloc fatal.");

	new->cb = cb;
	new->cb_arg = cb_arg;

	list_add(&new->node, chain);

	return 0;
}

static __unused void launch_chain(struct list_head *chain)
{
	struct callback *cb, *tmp;

	list_for_each_entry_safe(cb, tmp, chain, node) {
		cb->cb(cb->cb_arg);
	}
}

static __unused int destroy_chain(struct list_head *chain)
{
	struct callback *cb, *tmp;

	list_for_each_entry_safe(cb, tmp, chain, node) {
		list_del(&cb->node);
		free(cb);
	}

	return 0;
}

