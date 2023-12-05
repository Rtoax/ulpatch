#include <stdio.h>
#include <upatch/meta.h>


int local_i = 123;
static int static_i = 1024;
static int static_i2;
char *local_s = "Dear";
static char *static_s = "you";

void upatch_print_hello(void)
{
	int a = 10;

	local_i++;
	static_i++;
	static_i2++;

	printf("Hello World. Patched %d, %d, %d, %d\n",
		local_i, static_i, static_i2, a);
	printf("%s %s\n", local_s, static_s);
}
UPATCH_INFO(upatch, upatch_print_hello, print_hello, "Rong Tao");
