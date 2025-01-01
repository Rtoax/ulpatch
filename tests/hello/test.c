// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>

#define ULP_SYM(f)	void ulp_##f(unsigned long ul);
#include "ulp_funsym.h"
#undef ULP_SYM

/* see hello.c */
void internal_print_hello(unsigned long ul) {}

int main(void)
{
#define ULP_SYM(f) {	\
		printf("Testing %s\n", #f);	\
		ulp_##f(3);	\
		printf("\n");	\
	}
#include "ulp_funsym.h"
#undef ULP_SYM

	return 0;
}
