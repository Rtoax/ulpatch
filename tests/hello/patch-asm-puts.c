// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <ulpatch/meta.h>

void ulp_asm_puts(unsigned long ul)
{
	/* puts("Hello") */
#if defined(__x86_64__)
	__asm__("push %rax\n"
		"mov $0x0000006f6c6c6548, %rax\n"
		"push %rax\n"
		"mov %rsp, %rdi\n"
		"call puts\n"
		"pop %rax\n"
		"pop %rax\n");
#elif defined(__aarch64__)
	asm(
	"stp	x29, x30, [sp, #-32]!\n"
	"mov	x29, sp\n"
	"mov	w0, #0x48\n"                  	// #72
	"strb	w0, [sp, #24]\n"
	"mov	w0, #0x65\n"                  	// #101
	"strb	w0, [sp, #25]\n"
	"mov	w0, #0x6c\n"                  	// #108
	"strb	w0, [sp, #26]\n"
	"mov	w0, #0x6c\n"                  	// #108
	"strb	w0, [sp, #27]\n"
	"mov	w0, #0x6f\n"                  	// #111
	"strb	w0, [sp, #28]\n"
	"add	x0, sp, #0x18\n"
	"bl	puts\n"
	"mov	w0, #0x0\n"                   	// #0
	"ldp	x29, x30, [sp], #32\n");
#else
# warning Not supported CPU architecture yet.
#endif
}
ULPATCH_INFO(ulp_asm_puts, print_hello);
ULPATCH_AUTHOR("Rong Tao");
