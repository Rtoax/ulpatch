// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once
#include <string.h>
#include <sys/types.h>

struct task_struct;

int memcpy_to_task(struct task_struct *task, unsigned long remote_dst,
		   void *src, ssize_t size);
int memcpy_from_task(struct task_struct *task, void *dst,
		     unsigned long remote_src, ssize_t size);
char *strcpy_from_task(struct task_struct *task, char *dst,
		       unsigned long task_src);
char *strcpy_to_task(struct task_struct *task, unsigned long task_dst,
		     char *src);
