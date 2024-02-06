// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>


const char *phdr_type_str_unsafe(GElf_Phdr *pphdr)
{
	switch (pphdr->p_type) {
	case PT_INTERP:	return "INTERP";
	case PT_LOAD:	return "LOAD";
	/* TODO: more */
	}
	return "Unknown, see /usr/include/elf.h";
}

const char *phdr_flags_str_unsafe(GElf_Phdr *pphdr)
{
	static char prot[4];
	memset(prot, 0x00, sizeof(prot));
	prot[0] = pphdr->p_flags & PF_R ? 'R' : ' ';
	prot[1] = pphdr->p_flags & PF_W ? 'W' : ' ';
	prot[2] = pphdr->p_flags & PF_X ? 'X' : ' ';
	return prot;
}

int print_phdr(FILE *fp, GElf_Phdr *pphdr, bool first)
{
	if (first) {
		fprintf(fp, "  %-8s %-16s %-16s %-16s\n",
			"Type", "Offset", "VirtAddr", "PhysAddr");
		fprintf(fp, "  %-8s %-16s %-16s %-8s %-8s\n",
			"", "FileSize", "MemSize", "Flags", "Align");
	}
	fprintf(fp, "  %-8s %016lx %016lx %016lx\n",
		phdr_type_str_unsafe(pphdr),
		pphdr->p_offset,
		pphdr->p_vaddr,
		pphdr->p_paddr);
	fprintf(fp, "  %-8s %016lx %016lx %-8s %08lx\n",
		"",
		pphdr->p_filesz,
		pphdr->p_memsz,
		phdr_flags_str_unsafe(pphdr),
		pphdr->p_align);

	return 0;
}

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
		case PT_LOAD:
			ldebug("get a PT_LOAD program header.\n");
			break;
		default:
			break;
		}
	}

	return 0;
}

