// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025 Rong Tao */
#include <utils/log.h>
#include <task/thread.h>
#include <task/task.h>


void init_thread_root(struct task_thread_root *root)
{
	memset(root, 0, sizeof(struct task_thread_root));
	list_init(&root->list);
}

void print_thread(FILE *fp, struct task_struct *task,
		  struct thread_struct *thread)
{
	fprintf(fp, "pid %d, tid %d\n", task->pid, thread->tid);
}
