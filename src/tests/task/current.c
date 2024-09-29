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
#include <task/task.h>
#include <tests/test-api.h>

TEST_STUB(task_current);

TEST(Utils_task, current_task, 0)
{
	int ret = 0;
	struct task_struct *task;

	/* Init current to zero_task */
	if (current != zero_task) {
		return -1;
	}

	task = open_task(getpid(), FTO_NONE);
	if (task != current) {
		ret = -1;
		goto close;
	}

	/* Test current */
	ulp_info("Comm %s\n", current->comm);

	/* Make sure we could write 'current' task */
	current->exe_bfd = (void *)1;

close:
	close_task(task);
	if (current != zero_task) {
		ret = -1;
	}
	return ret;
}

