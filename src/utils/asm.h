// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#pragma once

/* clang-format off */

#define GLOBAL(sym)				\
	.global sym;				\
	.type sym, %function;			\
sym:						\
	.global ulftrace_ ## sym;		\
	.hidden ulftrace_ ## sym;		\
	.type ulftrace_ ## sym, %function;	\
ulftrace_ ## sym:

#define ENTRY(sym)				\
	.global sym;				\
	.hidden sym;				\
	.type sym, %function;			\
sym:

#define END(sym)				\
	.size sym, .-sym;

