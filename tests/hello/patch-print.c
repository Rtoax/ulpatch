#include <stdio.h>
#include <upatch/meta.h>


extern void internal_print_hello(void);

static void upatch_internal_print_hello(void)
{
	printf("Hello World. Patched\n");
	internal_print_hello();
}

void upatch_print_hello_print(void)
{
	upatch_internal_print_hello();
}
UPATCH_INFO(upatch, upatch_print_hello_print, print_hello, "Rong Tao");
