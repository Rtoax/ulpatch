// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include "utils/utils.h"
#include "utils/log.h"
#include "task/task.h"

#include "arch/aarch64/instruments.h"
#include "arch/aarch64/ftrace.h"

/*
 * Replace a single instruction, which may be a branch or NOP.
 * If @validate == true, a replaced instruction is checked against 'old'.
 *
 * see linux:arch/arm64/kernel/ftrace.c
 */
int ftrace_modify_code(struct task_struct *task, unsigned long pc, uint32_t old,
		       uint32_t new, bool validate)
{
	uint32_t replaced;

	/*
	 * Note:
	 * We are paranoid about modifying text, as if a bug were to happen, it
	 * could cause us to read or write to someplace that could cause harm.
	 * Carefully read and modify the code with aarch64_insn_*() which uses
	 * probe_kernel_*(), and make sure what we read is what we expected it
	 * to be before modifying it.
	 */
	if (validate) {
		if (aarch64_insn_read(task, pc, &replaced))
			return -EFAULT;

		if (replaced != old) {
			return -EINVAL;
		}
	}

	if (aarch64_insn_write(task, pc, new)) {
		return -EPERM;
	}

	return 0;
}

