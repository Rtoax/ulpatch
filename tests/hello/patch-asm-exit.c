// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <ulpatch/asm.h>
#include <ulpatch/meta.h>


void ulp_asm_exit(unsigned long ul)
{
#ifndef __ulp_builtin_exit
#error "Not found __ulp_builtin_exit() macro"
#endif
	__ulp_builtin_exit(0x2);
}
ULPATCH_INFO(ulp_asm_exit, print_hello);
ULPATCH_AUTHOR("Rong Tao");
ULPATCH_LICENSE("GPL-2.0");
