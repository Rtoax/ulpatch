#include <stdio.h>
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include <ulpatch/meta.h>


void ulp_asm_write(unsigned long ul)
{
#if defined(__x86_64__)
	/* write("Hello\n") */
	asm(
		"mov    $0x1,%al\n"
		"mov    %al,%dil\n"
		"push   $0xa20206f\n"
		"push   $0x6c6c6548\n"
		"mov    %rsp,%rsi\n"
		"mov    $0xc,%dl\n"
		"syscall\n"
		"pop    %rsi\n"
		"pop    %rsi\n"
	);
#elif defined(__aarch64__)
	/* write("Hello\n") */
	asm(
		"stp	x29, x30, [sp, #-32]!\n"
		"mov	x29, sp\n"
		"str	xzr, [sp, #16]\n"
		"mov	w0, #0x48\n"
		"strb	w0, [sp, #16]\n"
		"mov	w0, #0x65\n"
		"strb	w0, [sp, #17]\n"
		"mov	w0, #0x6c\n"
		"strb	w0, [sp, #18]\n"
		"mov	w0, #0x6c\n"
		"strb	w0, [sp, #19]\n"
		"mov	w0, #0x6f\n"
		"strb	w0, [sp, #20]\n"
		"mov	w0, #0xa\n"
		"strb	w0, [sp, #21]\n"
		"add	x0, sp, #0x10\n"
		"str	x0, [sp, #24]\n"
		"\n"
		"mov	x0, #1\n"
		"ldr	x1, [sp, #24]\n"
		"mov	x2, #0x8\n"
		"mov	w8, #64\n"
		"svc	#0\n"
	);
#else
# warning Not supported CPU architecture yet.
#endif
}
ULPATCH_INFO(ulp_asm_write, print_hello, "Rong Tao");
