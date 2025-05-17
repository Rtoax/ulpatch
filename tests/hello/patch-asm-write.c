// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <ulpatch/asm.h>
#include <ulpatch/meta.h>


void ulp_asm_write(unsigned long ul)
{
	char msg[] = {"Hello-\n"};
	int len = 7;
#if !defined(__ulp_builtin_write) || !defined(__ulp_builtin_write_hello)
#error "Not found __ulp_builtin_write() or __ulp_builtin_write_hello()"
#endif
	__ulp_builtin_write(1, msg, len);
	__ulp_builtin_write_hello();
}
ULPATCH_INFO(ulp_asm_write, print_hello);
ULPATCH_AUTHOR("Rong Tao");
ULPATCH_LICENSE("GPL-2.0");
