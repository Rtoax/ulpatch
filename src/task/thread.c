// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025 Rong Tao */
#include <utils/log.h>
#include <task/thread.h>
#include <task/task.h>

void print_thread(FILE *fp, struct task_struct *task, struct thread *thread)
{
	fprintf(fp, "pid %d, tid %d\n", task->pid, thread->tid);
}

