// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once

struct task_struct;

#define current get_current_task()
#define zero_task __zero_task()

int set_current_task(struct task_struct *task);
void reset_current_task(void);
struct task_struct *const get_current_task(void);
struct task_struct *const __zero_task(void);
