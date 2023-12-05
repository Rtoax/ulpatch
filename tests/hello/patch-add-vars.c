#include <stdio.h>
#include <upatch/meta.h>


void upatch_print_hello(void)
{
	static int a = 0;
	a++;
	printf("Hello World. Patched %d\n", a);
}
UPATCH_INFO(upatch, upatch_print_hello, print_hello, "Rong Tao");
