// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025 Rong Tao */
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils/log.h"
#include "utils/list.h"
#include "task/task.h"
#include "tests/test-api.h"


TEST(Task_fd, base, 0)
{
	struct task_struct *task = open_task(getpid(), FTO_FD);
	dump_task_fds(stdout, task, true);
	return close_task(task);
}
