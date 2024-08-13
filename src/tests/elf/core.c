// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/compiler.h>

#include <elf/elf_api.h>

#include <tests/test_api.h>



TEST(Elf_Core, libc_object, 0)
{
	return libc_object() ? 0 : 1;
}

