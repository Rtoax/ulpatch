// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
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
#define __ulp_builtin_sleep_x86_64(sec) ({	\
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

#define __ulp_builtin_sleep_aarch64(sec) ({	\
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
# define __ulp_builtin_sleep(sec) __ulp_builtin_sleep_x86_64(sec)
#elif defined(__aarch64__)
# define __ulp_builtin_sleep(sec) __ulp_builtin_sleep_aarch64(sec)
#else
# error "__ulp_builtin_sleep() is not support on this architecture"
#endif


/**
 * SYNOPSIS: void exit(int status);
 */
#define __ulp_builtin_exit_x86_64(val) ({	\
	int ____v = val;			\
	int ____ret;				\
	__asm__("mov %1, %%edi \n\t"		\
		"movq $60, %%rax \n\t"		\
		"syscall \n\t"			\
		: "=r"(____ret)			\
		: "r"(____v));			\
	____ret;				\
})

#define __ulp_builtin_exit_aarch64(val) ({	\
	int ____v = val;			\
	__asm__("mov x0, %[v]\n"		\
		"mov w8, #0x5d\n"		\
		"svc #0x0\n"			\
		: /* no ret */			\
		: [v] "r"(____v));		\
})

#if defined(__x86_64__)
# define __ulp_builtin_exit(v) __ulp_builtin_exit_x86_64(v)
#elif defined(__aarch64__)
# define __ulp_builtin_exit(v) __ulp_builtin_exit_aarch64(v)
#else
# error "__ulp_builtin_exit() is not support on this architecture"
#endif


/**
 * SYNOPSIS: ssize_t write(int fd, const void buf[.count], size_t count);
 */
#define __ulp_builtin_write_x86_64(fd, msg, len) ({	\
	int ____ret;					\
	int ____fd = fd;				\
	char *____msg = msg;				\
	unsigned long ____len = len;			\
	__asm__("mov %[_fd], %%edi \n\t"		\
		"movq %[_msg], %%rsi \n\t"		\
		"movq %[_len], %%rdx \n\t"		\
		"movq $1, %%rax \n\t"			\
		"syscall \n\t"				\
		: "=r"(____ret)				\
		: [_fd] "r"(____fd),			\
		  [_msg] "r"(____msg),			\
		  [_len] "r"(____len));			\
	____ret;					\
})

/* write(1, "Hello\n", 6) */
#define __ulp_builtin_write_hello_x86_64() ({	\
	__asm__("mov $0x1, %al\n"		\
		"mov %al, %dil\n"		\
		"push $0x00000a6f\n"		\
		"push $0x6c6c6548\n"		\
		"mov %rsp, %rsi\n"		\
		"mov $0xc, %dl\n"		\
		"syscall\n"			\
		"pop %rsi\n"			\
		"pop %rsi\n");			\
})

#define __ulp_builtin_write_aarch64(fd, msg, len) ({	\
	int ____ret;					\
	int ____fd = fd;				\
	char *____msg = msg;				\
	unsigned long ____len = len;			\
	__asm__("stp x0, x1, [sp, #-32]! \n\t"		\
		"mov x0, %[_fd] \n\t"			\
		"mov x1, %[_msg] \n\t"			\
		"mov x2, %[_len] \n\t"			\
		"mov x8, #64 \n\t"			\
		"svc #0 \n\t"				\
		"ldp x0, x1, [sp], #32 \n\t"		\
		: "=g"(____ret)				\
		: [_fd] "r"(____fd),			\
		  [_msg] "r"(____msg),			\
		  [_len] "r"(____len));			\
	____ret;					\
})

#define __ulp_builtin_write_hello_aarch64() ({	\
	__asm__("stp x29, x30, [sp, #-32]!\n"	\
		"mov x29, sp\n"			\
		"str xzr, [sp, #16]\n"		\
		"mov w0, #0x48\n"		\
		"strb w0, [sp, #16]\n"		\
		"mov w0, #0x65\n"		\
		"strb w0, [sp, #17]\n"		\
		"mov w0, #0x6c\n"		\
		"strb w0, [sp, #18]\n"		\
		"mov w0, #0x6c\n"		\
		"strb w0, [sp, #19]\n"		\
		"mov w0, #0x6f\n"		\
		"strb w0, [sp, #20]\n"		\
		"mov w0, #0xa\n"		\
		"strb w0, [sp, #21]\n"		\
		"add x0, sp, #0x10\n"		\
		"str x0, [sp, #24]\n"		\
		"\n"				\
		"mov x0, #1\n"			\
		"ldr x1, [sp, #24]\n"		\
		"mov x2, #0x8\n"		\
		"mov w8, #64\n"			\
		"svc #0\n"			\
		"ldp x29, x30, [sp], #32\n");	\
})

#if defined(__x86_64__)
# define __ulp_builtin_write(fd, msg, len) __ulp_builtin_write_x86_64(fd, msg, len)
# define __ulp_builtin_write_hello() __ulp_builtin_write_hello_x86_64()
#elif defined(__aarch64__)
# define __ulp_builtin_write(fd, msg, len) __ulp_builtin_write_aarch64(fd, msg, len)
# define __ulp_builtin_write_hello() __ulp_builtin_write_hello_aarch64()
#else
# error "__ulp_builtin_write() or __ulp_builtin_write_hello() is not support on this architecture"
#endif

