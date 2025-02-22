// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once

#define mcount_regs mcount_regs

struct mcount_regs {
	unsigned long r9;
	unsigned long r8;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
};

#define ARG1(a) ((a)->rdi)
#define ARG2(a) ((a)->rsi)
#define ARG3(a) ((a)->rdx)
#define ARG4(a) ((a)->rcx)
#define ARG5(a) ((a)->r8)
#define ARG6(a) ((a)->r9)

