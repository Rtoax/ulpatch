#include <stdio.h>
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include <ulpatch/meta.h>


void ulpatch_print_hello(void)
{
#if defined(__x86_64__)
	asm(
	"push   $0x44434241\n"
	"mov    %rsp,%rdi\n"
	"call   puts\n"
	"pop    %rsi\n");
#else
# warning Not supported CPU architecture yet.
#endif
}
ULPATCH_INFO(ulpatch, ulpatch_print_hello, print_hello, "Rong Tao");
