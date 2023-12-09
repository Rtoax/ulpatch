#include <stdio.h>
#include <ulpatch/meta.h>

/**
 * TODO: .bss NOBITS not exist in relocatable ELF file.
 */
static int static_i;

void ulpatch_print_hello(void)
{
	static_i += 2;
}
ULPATCH_INFO(ulpatch, ulpatch_print_hello, print_hello, "Rong Tao");
