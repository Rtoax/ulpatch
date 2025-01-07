// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <limits.h>
#include <stdlib.h>
#include <elf.h>
#include <dirent.h>

#include <elf/elf-api.h>

#include <utils/log.h>
#include <task/task.h>


/**
 * We should implement the current macro because sometimes we cannot directly
 * pass the task_struct structure as a function parameter. At the same time,
 * this can also be unified with the kernel.
 */
static struct task_struct *current_task = NULL;
static struct task_struct fallback_task = {
	.pid = 0,
	.fto_flag = 0,
	.exe = "??",
};

int set_current_task(struct task_struct *task)
{
	if (!task)
		return -EINVAL;
	current_task = task;
	return 0;
}

void reset_current_task(void)
{
	current_task = &fallback_task;
}

/**
 * Use to check current is set or not.
 */
struct task_struct *const __zero_task(void)
{
	return &fallback_task;
}

struct task_struct *const get_current_task(void)
{
	if (!current_task) {
		errno = ENOENT;
		/**
		 * To prevent segmentation errors, NULL cannot be returned.
		 */
		return &fallback_task;
	}
	return current_task;
}

