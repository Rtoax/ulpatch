// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdint.h>
#include <stdbool.h>


struct task_struct;

int ftrace_modify_code(struct task_struct *task, unsigned long pc, uint32_t old,
		       uint32_t new, bool validate);
