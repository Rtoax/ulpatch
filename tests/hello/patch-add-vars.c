#include <stdio.h>
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include <ulpatch/meta.h>


int local_i = 123;
long int local_l = 123;
static long static_i = 1024;
char *local_s = "Dear";
static char *static_s = "you";

void ulp_add_var(unsigned long ul)
{
	int i, a = 10;

	local_i++;
	local_l++;
	static_i++;
	static_i += 2;

	printf("Hello World. Patched %ld %d, %ld, %d, %d\n",
		ul, local_i, local_l, static_i, a);
	printf("%s %s\n", local_s, static_s);

	for (i = 0; i < 3; i++)
		printf("- %d -\n", i);
}
ULPATCH_INFO(ulp_add_var, print_hello, "Rong Tao");
