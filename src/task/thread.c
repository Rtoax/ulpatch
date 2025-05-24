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

struct thread_struct *alloc_thread(pid_t tid)
{
	struct thread_struct *thread;
	thread = malloc(sizeof(struct thread_struct));
	thread->tid = tid;
	list_init(&thread->node);
	return thread;
}

void free_thread(struct thread_struct *thread)
{
	list_del(&thread->node);
	free(thread);
}

void print_thread(FILE *fp, struct task_struct *task,
		  struct thread_struct *thread)
{
	fprintf(fp, "pid %d, tid %d\n", task->pid, thread->tid);
}

void dump_task_threads(FILE *fp, struct task_struct *task, bool detail)
{
	struct thread_struct *thread;

	if (!fp)
		fp = stdout;

	if (!(task->fto_flag & FTO_THREADS)) {
		ulp_error("Not set FTO_THREADS(%ld) flag\n", FTO_THREADS);
		return;
	}

	list_for_each_entry(thread, &task->thread_root.list, node)
		print_thread(fp, task, thread);
}
