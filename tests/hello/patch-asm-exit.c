// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdio.h>
#include <ulpatch/asm.h>
#include <ulpatch/meta.h>


void ulp_asm_exit(unsigned long ul)
{
#ifdef __ulp_builtin_exit
	__ulp_builtin_exit(0x2);
#endif
}
ULPATCH_INFO(ulp_asm_exit, print_hello, "Rong Tao");
