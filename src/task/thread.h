// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once
#include <sys/types.h>

#include <utils/list.h>

/* see /usr/include/sys/user.h */
#if defined(__x86_64__)
typedef unsigned long long int pc_addr_t;
#elif defined(__aarch64__)
typedef unsigned long long pc_addr_t;
#else
# error Not support architecture
#endif

struct task_struct;

struct thread_struct {
	pid_t tid;
	/* TODO */
	pc_addr_t ip;
	/* struct task_thread_root.list */
	struct list_head node;
};

struct task_thread_root {
	/* struct thread_struct.node */
	struct list_head list;
};

void init_thread_root(struct task_thread_root *root);

void print_thread(FILE *fp, struct task_struct *task,
		  struct thread_struct *thread);
