#include <stdio.h>
#include <ulpatch/asm.h>
#include <ulpatch/meta.h>


void ulp_asm_exit(unsigned long ul)
{
#if defined(__x86_64__)
	/* exit(0xff) */
	asm(
		"mov    $0x3c,%eax\n"
		"xor    $0xff,%rdi\n"
		"syscall\n"
	);
#elif defined(__aarch64__)
	ASM_EXIT(0x2);
#else
# warning Not supported CPU architecture yet.
#endif
}
ULPATCH_INFO(ulp_asm_exit, print_hello, "Rong Tao");
