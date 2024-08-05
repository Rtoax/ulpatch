#include <stdio.h>
#include <ulpatch/asm.h>
#include <ulpatch/meta.h>


void ulp_asm_write(unsigned long ul)
{
	char msg[] = {"Hello-\n"};
	int len = 7;
#if defined(__x86_64__) || defined(__aarch64__)
	ASM_WRITE(1, msg, len);
	ASM_WRITE_HELLO();
#else
# warning Not supported CPU architecture yet.
#endif
}
ULPATCH_INFO(ulp_asm_write, print_hello, "Rong Tao");
