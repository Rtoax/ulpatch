#include <stdio.h>
#include <upatch/meta.h>


void func1(void)
{
	printf("Hello patched.\n");
}

void upatch_print_hello(void)
{
	func1();
}
UPATCH_INFO(upatch, upatch_print_hello, print_hello, "Rong Tao");
