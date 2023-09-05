// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#pragma once

#define mcount_regs mcount_regs

struct mcount_regs {
	unsigned long x0;
	unsigned long x1;
	unsigned long x2;
	unsigned long x3;
	unsigned long x4;
	unsigned long x5;
	unsigned long x6;
	unsigned long x7;
};

#define ARG1(a) ((a)->x0)
#define ARG2(a) ((a)->x1)
#define ARG3(a) ((a)->x2)
#define ARG4(a) ((a)->x3)
#define ARG5(a) ((a)->x4)
#define ARG6(a) ((a)->x5)
#define ARG7(a) ((a)->x6)
#define ARG8(a) ((a)->x7)



