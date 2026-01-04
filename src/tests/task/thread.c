// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025-2026 Rong Tao */
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>

#include "utils/log.h"
#include "utils/list.h"
#include "task/task.h"
#include "tests/test-api.h"


TEST(Task_thread, base, 0)
{
	struct task_struct *task = open_task(getpid(), FTO_THREADS);
	dump_task_threads(stdout, task, true);
	return close_task(task);
}
