// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024-2025 Rong Tao */
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include "patch/meta.h"

void empty_hello_world(void)
{
}
ULPATCH_INFO(empty_hello_world, hello_world);
ULPATCH_AUTHOR("Rong Tao");
ULPATCH_LICENSE("GPL-2.0");
