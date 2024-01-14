#include <stdio.h>
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include <ulpatch/meta.h>


void ulpatch_print_hello_exit(unsigned long ul)
{
#if defined(__x86_64__)
	/* exit(0xff) */
	asm(
		"mov    $0x3c,%eax\n"
		"xor    $0xff,%rdi\n"
		"syscall\n"
	);
#elif defined(__aarch64__)
	/* exit(0xff) */
	asm(
		"mov    x0, #0xff\n"
		"mov    w8, #0x5d\n"
		"svc    #0x0\n"
	);
#else
# warning Not supported CPU architecture yet.
#endif
}
ULPATCH_INFO(ulpatch_print_hello_exit, print_hello, "Rong Tao");
