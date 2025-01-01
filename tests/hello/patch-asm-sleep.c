// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <ulpatch/asm.h>
#include <ulpatch/meta.h>


void ulp_asm_sleep(unsigned long ul)
{
	__ulp_builtin_sleep(1);
}
ULPATCH_INFO(ulp_asm_sleep, print_hello, "Rong Tao");
