// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include <stdio.h>
#include <patch/asm.h>
#include <patch/meta.h>

void printf_hello_world(void)
{
	printf("Hello World from ulpatch.\n");
}
ULPATCH_INFO(printf_hello_world, hello_world);
ULPATCH_AUTHOR("Rong Tao");
