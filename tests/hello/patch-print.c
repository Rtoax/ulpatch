// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <ulpatch/asm.h>
#include <ulpatch/meta.h>


extern void internal_print_hello(unsigned long ul);

static void ulpatch_internal_print_hello(unsigned long ul)
{
#if !defined(NO_LIBC)
# if defined(STACK)
	char buff[] = {"Hello World. Patched\n"};
	printf(buff);
# else
	printf("Hello World. Patched\n");
# endif
#endif
	internal_print_hello(ul);
}

void ulp_print(unsigned long ul)
{
	ulpatch_internal_print_hello(ul);
}
ULPATCH_INFO(ulp_print, print_hello);
ULPATCH_AUTHOR("Rong Tao");
