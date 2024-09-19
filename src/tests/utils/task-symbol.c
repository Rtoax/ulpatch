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
		ulp_info("TSYM: %s %lx\n", tsym->name, tsym->addr);
	}

	return close_task(task);
}

