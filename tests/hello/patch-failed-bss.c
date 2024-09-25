// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdio.h>
#include <ulpatch/meta.h>

/**
 * TODO: .bss NOBITS not exist in relocatable ELF file.
 */
static int static_i;

void ulp_failed_bss(unsigned long ul)
{
	static_i += 2;
	printf("static_i = %d\n", static_i);
}
ULPATCH_INFO(ulp_failed_bss, print_hello, "Rong Tao");
