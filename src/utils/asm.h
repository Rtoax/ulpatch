// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 CESTC, Co. Rong Tao <rongtao@cestc.cn> */
#pragma once

/* clang-format off */

#define GLOBAL(sym)				\
	.global sym;				\
	.type sym, %function;			\
sym:						\
	.global uftrace_ ## sym;		\
	.hidden uftrace_ ## sym;		\
	.type uftrace_ ## sym, %function;	\
uftrace_ ## sym:

#define ENTRY(sym)				\
	.global sym;				\
	.hidden sym;				\
	.type sym, %function;			\
sym:

#define END(sym)				\
	.size sym, .-sym;

