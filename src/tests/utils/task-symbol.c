// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/task.h>
#include <tests/test-api.h>


TEST(Task_sym, for_each, 0)
{
	struct task_struct *task = open_task(getpid(), FTO_ULPATCH);
	struct task_sym *tsym;

	for (tsym = next_task_sym(task, NULL); tsym;
	     tsym = next_task_sym(task, tsym))
	{
		ulp_info("TSYM: %s 0x%016lx\n", tsym->name, tsym->addr);
	}

	for (tsym = next_task_addr(task, NULL); tsym;
	     tsym = next_task_addr(task, tsym))
	{
		ulp_info("TADDR: 0x%016lx %s\n", tsym->addr, tsym->name);
		if (!list_empty(&tsym->list_node_or_head)) {
			struct task_sym *s, *tmp;
			list_for_each_entry_safe(s, tmp,
			    &tsym->list_node_or_head, list_node_or_head) {
				ulp_info("TADDR: SUB 0x%016lx %s\n", s->addr,
					 s->name);
			}
		}
	}

	return close_task(task);
}

