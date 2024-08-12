// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdint.h>
#include <stdbool.h>


const char *ftrace_nop_replace(void);
const char *ftrace_call_replace(union text_poke_insn *insn, unsigned long ip,
				unsigned long addr);

