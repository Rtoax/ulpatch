#include <stdio.h>
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include <ulpatch/meta.h>


int local_i = 123;
long int local_l = 123;
char *local_s = "Dear";
#if !defined(NOSTATIC)
static long static_i = 1024;
static char *static_s = "you";
#endif

void ulp_add_var(unsigned long ul)
{
	int i, a = 10;

	local_i++;
	local_l++;
#if !defined(NOSTATIC)
	static_i++;
	static_i += 2;
#endif

#if !defined(NOLIBC)
	printf("Hello World. Patched L: %d, %ld, %s\n", local_i, local_l, local_s);
	printf("Hello World. Patched F: %ld %d\n", ul, a);

	for (i = 0; i < 3; i++)
		printf("%d\n", i);

	/* FIXME: This will segfault. Why? */
	//printf("\n");

# if !defined(NOSTATIC)
	printf("Hello World. Patched S: %d %s\n", static_i, static_s);
# endif
#endif
}
ULPATCH_INFO(ulp_add_var, print_hello, "Rong Tao");
