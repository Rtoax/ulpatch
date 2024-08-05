// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao <rtoax@foxmail.com> */
#pragma once

/**
 * You can use the interface provided by this assembly header file directly in
 * your UPL patch. This does not produce any relocation entries in the ELF
 * patch file, so this is useful for testing.
 *
 * Developers note that any header file included in this header file can only
 * reference the data structure in it, not any interfaces.
 */
#include <time.h>

/**
 * nanosleep(2)
 * SYNOPSIS: int nanosleep(const struct timespec *req, struct timespec *rem);
 */
#define ASM_SLEEP_X86_64(sec) ({		\
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


/**
 * SYNOPSIS: void exit(int status);
 */
#define ASM_EXIT_X86_64(val) ({		\
	int ____v = val;		\
	int ____ret;			\
	__asm__("mov %1, %%edi \n\t"	\
		"movq $60, %%rax \n\t"	\
		"syscall \n\t"		\
		: "=r"(____ret)		\
		: "r"(____v));		\
	____ret;			\
})

#define ASM_EXIT_AARCH64(val) ({	\
	int ____v = val;		\
	__asm__("mov x0, %[v]\n"	\
		"mov w8, #0x5d\n"	\
		"svc #0x0\n"		\
		: /* no ret */		\
		: [v] "r"(____v));	\
})

#if defined(__x86_64__)
# define ASM_EXIT(v) ASM_EXIT_X86_64(v)
#elif defined(__aarch64__)
# define ASM_EXIT(v) ASM_EXIT_AARCH64(v)
#else
# error "ASM_EXIT() is not support"
#endif


/**
 * SYNOPSIS: ssize_t write(int fd, const void buf[.count], size_t count);
 */
#define ASM_WRITE_X86_64(fd, msg, len) ({	\
	int ____ret;				\
	int ____fd = fd;			\
	char *____msg = msg;			\
	unsigned long ____len = len;		\
	__asm__("mov %[_fd], %%edi \n\t"	\
		"movq %[_msg], %%rsi \n\t"	\
		"movq %[_len], %%rdx \n\t"	\
		"movq $1, %%rax \n\t"		\
		"syscall \n\t"			\
		: "=r"(____ret)			\
		: [_fd] "r"(____fd),		\
		  [_msg] "r"(____msg),		\
		  [_len] "r"(____len));		\
})

/* write(1, "Hello\n", 6) */
#define ASM_WRITE_HELLO_X86_64() ({	\
	__asm__("mov $0x1, %al\n"	\
		"mov %al, %dil\n"	\
		"push $0xa20206f\n"	\
		"push $0x6c6c6548\n"	\
		"mov %rsp, %rsi\n"	\
		"mov $0xc, %dl\n"	\
		"syscall\n"		\
		"pop %rsi\n"		\
		"pop %rsi\n");		\
})

#if defined(__x86_64__)
# define ASM_WRITE(fd, msg, len) ASM_WRITE_X86_64(fd, msg, len)
# define ASM_WRITE_HELLO() ASM_WRITE_HELLO_X86_64()
#elif defined(__aarch64__)
#else
# error "ASM_WRITE() is not support"
#endif

