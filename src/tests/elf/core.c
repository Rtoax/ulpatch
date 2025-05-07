// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024-2025 Rong Tao */
#include <errno.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/compiler.h>
#include <elf/elf-api.h>
#include <tests/test-api.h>


TEST(Elf_Core, libc_object, 0)
{
	/* Must has libc.so */
	return libc_object() ? 0 : 1;
}
