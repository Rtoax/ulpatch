#include <stdio.h>
#include <upatch/meta.h>


void upatch_print_hello(void)
{
	// TODO: Not support library function yet
	//printf("Hello World. Patched\n");
}

UPATCH_INFO(upatch, upatch_print_hello, print_hello, "Rong Tao");
