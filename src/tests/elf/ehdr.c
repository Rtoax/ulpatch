// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <errno.h>
#include "utils/log.h"
#include "utils/list.h"
#include "utils/util.h"
#include "elf/elf-api.h"
#include "tests/test-api.h"


TEST(Elf_Ehdr, print, 0)
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
	return print_ehdr(NULL, &ehdr1);
}

TEST(Elf_Ehdr, readelf, 0)
{
	int ret;
	struct elf_file *elf;
	elf = elf_file_open(ulpatch_test_path);
	if (!elf) {
		ulp_error("open %s failed.\n", ulpatch_test_path);
		return -ENOENT;
	}

	ret = print_ehdr(stdout, elf->ehdr);

	elf_file_close(ulpatch_test_path);
	return ret;
}
