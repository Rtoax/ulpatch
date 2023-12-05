#include <stdio.h>
#include <upatch/meta.h>


void upatch_print_hello(void)
{
	/* TODO, support 100 */
	printf("Hello World. Patched %d\n", 100);
}
UPATCH_INFO(upatch, upatch_print_hello, print_hello, "Rong Tao");
