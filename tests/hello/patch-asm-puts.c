#include <stdio.h>
#include <upatch/meta.h>


void upatch_print_hello(void)
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
UPATCH_INFO(upatch, upatch_print_hello, print_hello, "Rong Tao");
