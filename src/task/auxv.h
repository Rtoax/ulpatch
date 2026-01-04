// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#pragma once
#include <sys/types.h>

struct task_struct;

/**
 * Store values of the auxiliary vector, read from /proc/PID/auxv
 */
struct task_auxv {
	/* AT_PHDR */
	unsigned long auxv_phdr;
	/* AT_PHENT */
	unsigned long auxv_phent;
	/* AT_PHNUM */
	unsigned long auxv_phnum;
	/* AT_BASE */
	unsigned long auxv_interp;
	/* AT_ENTRY */
	unsigned long auxv_entry;
};


int load_task_auxv(pid_t pid, struct task_auxv *pauxv);
int print_task_auxv(FILE *fp, const struct task_struct *task);
