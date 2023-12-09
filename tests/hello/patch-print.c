#include <stdio.h>
#include <ulpatch/meta.h>


extern void internal_print_hello(void);

static void ulpatch_internal_print_hello(void)
{
	printf("Hello World. Patched\n");
	internal_print_hello();
}

void ulpatch_print_hello_print(void)
{
	ulpatch_internal_print_hello();
}
ULPATCH_INFO(ulpatch, ulpatch_print_hello_print, print_hello, "Rong Tao");
