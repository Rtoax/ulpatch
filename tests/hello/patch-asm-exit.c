#include <stdio.h>
#include <ulpatch/asm.h>
#include <ulpatch/meta.h>


void ulp_asm_exit(unsigned long ul)
{
#ifdef ASM_EXIT
	ASM_EXIT(0x2);
#endif
}
ULPATCH_INFO(ulp_asm_exit, print_hello, "Rong Tao");
