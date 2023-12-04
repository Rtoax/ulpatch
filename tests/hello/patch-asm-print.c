#include <stdio.h>
#include <upatch/meta.h>


void upatch_print_hello_exit(void)
{
#if defined(__x86_64__)
	/* write("Hello") */
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
#else
# warning Not supported CPU architecture yet.
#endif
}
UPATCH_INFO(upatch, upatch_print_hello_exit, print_hello, "Rong Tao");
