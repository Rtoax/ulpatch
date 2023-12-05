#include <stdio.h>
#include <upatch/meta.h>

/**
 * TODO: .bss NOBITS not exist in relocatable ELF file.
 */
static int static_i;

void upatch_print_hello(void)
{
	static_i += 2;
}
UPATCH_INFO(upatch, upatch_print_hello, print_hello, "Rong Tao");
