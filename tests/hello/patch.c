#include <stdio.h>
#include <upatch/meta.h>


void print_hello(void)
{
	printf("Hello World. Patched\n");
}

UPATCH_INFO(upatch, print_hello, print_hello, "Rong Tao");
