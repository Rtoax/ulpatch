#include <stdio.h>
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include <ulpatch/meta.h>


extern void internal_print_hello(unsigned long ul);

static void ulpatch_internal_print_hello(unsigned long ul)
{
	printf("Hello World. Patched\n");
	internal_print_hello(ul);
}

void ulp_print(unsigned long ul)
{
	ulpatch_internal_print_hello(ul);
}
ULPATCH_INFO(ulp_print, print_hello, "Rong Tao");
