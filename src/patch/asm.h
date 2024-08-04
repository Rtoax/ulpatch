// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao <rtoax@foxmail.com> */
#pragma once

#include <time.h>

/**
 * You can use the interface provided by this assembly header file directly in
 * your UPL patch.
 */

/**
 * nanosleep(2) __NR_nanosleep=35
 */
#define ASM_SLEEP_X86_64(sec) ({			\
	int ____ret;				\
	struct timespec ____ts = {sec, 0};	\
	__asm__("movq %1, %%rdi \n\t"		\
		"xor %%rsi, %%rsi \n\t"		\
		"movq $35, %%rax \n\t"		\
		"syscall \n\t"			\
		: "=r"(____ret)			\
		: "r"(&____ts));		\
	____ret;				\
})

#define ASM_SLEEP_AARCH64(sec) ({		\
	int ____ret;				\
	struct timespec ____ts = {sec, 0};	\
	__asm__("stp x0, x1, [sp, #-16]! \n\t"	\
		"mov x0, %[pts] \n\t"		\
		"mov x1, %[rem] \n\t"		\
		"mov x8, #0x65 \n\t"		\
		"svc #0 \n\t"			\
		"ldp x0, x1, [sp], #16 \n\t"	\
		: "=g"(____ret)			\
		: [pts] "r"(&____ts),		\
		  [rem] "g"(0));		\
	____ret;				\
})


#if defined(__x86_64__)
# define ASM_SLEEP(sec) ASM_SLEEP_X86_64(sec)
#elif defined(__aarch64__)
# define ASM_SLEEP(sec) ASM_SLEEP_AARCH64(sec)
#else
# error "ASM_SLEEP() is not support"
#endif

