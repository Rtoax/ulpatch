// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once
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

/* callback chain */
struct callback_chain {
	struct list_head head;
};


int insert_callback(struct callback_chain *chain, int (*cb)(void *arg),
		    void *cb_arg);
void callback_launch_chain(struct callback_chain *chain);
int destroy_callback_chain(struct callback_chain *chain);
