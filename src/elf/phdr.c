// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 CESTC, Co. Rong Tao <rongtao@cestc.cn> */
#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>


int handle_phdrs(struct elf_file *elf)
{
	struct elf_iter iter;

	elf_for_each_phdr(elf, &iter) {
		GElf_Phdr *phdr = iter.phdr;

		switch (phdr->p_type) {
		case PT_INTERP:
			elf->elf_interpreter = elf->rawfile + phdr->p_offset;
			ldebug("[Requesting program interpreter: %s]\n",
				elf->elf_interpreter);
			break;
		default:
			break;
		}
	}

	return 0;
}

