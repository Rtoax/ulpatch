#include <stdio.h>
#include <upatch/meta.h>


void func1(void)
{
	/* TODO */
}

void upatch_print_hello(void)
{
	func1();
}
UPATCH_INFO(upatch, upatch_print_hello, print_hello, "Rong Tao");
