#include <stdio.h>
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include <ulpatch/meta.h>

/**
 * TODO: .bss NOBITS not exist in relocatable ELF file.
 */
static int static_i;

void ulpatch_print_hello(unsigned long ul)
{
	static_i += 2;
}
ULPATCH_INFO(ulpatch_print_hello, print_hello, "Rong Tao");
