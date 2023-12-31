// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <stdio.h>
#include <patch/patch.h>

/* TODO */

void new_hello_world(void)
{
	printf("Hello World from ulpatch.\n");
}

ULPATCH_INFO(ulpatch, new_hello_world, hello_world, "Rong Tao");

