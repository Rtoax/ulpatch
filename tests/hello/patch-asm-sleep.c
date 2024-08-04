#include <stdio.h>
#include <ulpatch/asm.h>
#include <ulpatch/meta.h>


void ulp_asm_sleep(unsigned long ul)
{
#ifdef ASM_SLEEP
	ASM_SLEEP(1);
#endif
}
ULPATCH_INFO(ulp_asm_sleep, print_hello, "Rong Tao");
