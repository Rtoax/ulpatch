// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <ulpatch/meta.h>


int local_i = 123;
long int local_l = 123;
char *local_s = "Dear";
#if !defined(NO_STATIC_VAR)
static long static_l = 1024;
static char *static_s = "you";
#endif

void ulp_add_var(unsigned long ul)
{
	int i, a = 10;

	local_i++;
	local_l++;
#if !defined(NO_STATIC_VAR)
	static_l++;
	static_l += 2;
#endif

#if !defined(NOLIBC)
	printf("Hello World. Patched L: %d, %ld, %s\n", local_i, local_l, local_s);
	printf("Hello World. Patched F: %ld %d\n", ul, a);

	for (i = 0; i < 3; i++)
		printf("%d\n", i);

	/* FIXME: This will segfault. Why? */
	//printf("\n");

# if !defined(NO_STATIC_VAR)
	printf("Hello World. Patched S: %ld %s\n", static_l, static_s);
# endif
#endif
}
ULPATCH_INFO(ulp_add_var, print_hello);
ULPATCH_AUTHOR("Rong Tao");
ULPATCH_LICENSE("GPL-2.0");
