// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <ulpatch/meta.h>

void ulp_empty(unsigned long ul)
{
}
ULPATCH_INFO(ulp_empty, print_hello);
ULPATCH_AUTHOR("Rong Tao");
ULPATCH_LICENSE("GPL-2.0");
