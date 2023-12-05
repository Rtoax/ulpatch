#include <stdio.h>
#include <upatch/meta.h>


int local_i = 123;
static long static_i = 1024;
char *local_s = "Dear";
static char *static_s = "you";

void upatch_print_hello(void)
{
	int i, a = 10;

	local_i++;
	static_i++;
	static_i += 2;

	printf("Hello World. Patched %d, %d, %d\n", local_i, static_i, a);
	printf("%s %s\n", local_s, static_s);

	for (i = 0; i < 3; i++)
		printf("- %d -\n", i);
}
UPATCH_INFO(upatch, upatch_print_hello, print_hello, "Rong Tao");
