// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <elf/elf_api.h>

#include "../test_api.h"

TEST(Elf_Ehdr,	print,	0)
{
	Elf64_Ehdr ehdr1 = {
		.e_ident[EI_MAG0] = ELFMAG0,
		.e_ident[EI_MAG1] = ELFMAG1,
		.e_ident[EI_MAG2] = ELFMAG2,
		.e_ident[EI_MAG3] = ELFMAG3,
		.e_type = ET_EXEC,
		.e_version = EV_CURRENT,
		.e_entry = 0xffff,
	};
	print_ehdr(NULL, &ehdr1);
	return 0;
}
