// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include <utils/util.h>
#include <utils/log.h>
#include <utils/task.h>

#include "instruments.h"
#include "ftrace.h"
#include "nops.h"

const char *ftrace_nop_replace(void)
{
	return (const char *)ideal_nops[NOP_ATOMIC5];
}

const char *ftrace_call_replace(union text_poke_insn *insn, unsigned long ip,
			unsigned long addr)
{
	return text_gen_insn(insn, INST_CALL, (void *)ip, (void *)addr);
}

