#include <stdio.h>
#include <upatch/meta.h>


void upatch_print_hello_exit(void)
{
#if defined(__x86_64__)
	/* exit(0xff) */
	asm(
		"mov    $0x3c,%eax\n"
		"xor    $0xff,%rdi\n"
		"syscall\n"
	);
#else
# warning Not supported CPU architecture yet.
#endif
}
UPATCH_INFO(upatch, upatch_print_hello_exit, print_hello, "Rong Tao");
