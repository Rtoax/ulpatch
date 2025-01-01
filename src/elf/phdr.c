// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include <elf/elf-api.h>
#include <utils/util.h>
#include <utils/log.h>


const char *phdr_type_str(GElf_Phdr *pphdr)
{
	switch (pphdr->p_type) {
	case PT_NULL: return "NULL";
	case PT_LOAD:	return "LOAD";
	case PT_DYNAMIC: return "DYNAMIC";
	case PT_INTERP:	return "INTERP";
	case PT_NOTE: return "NOTE";
	case PT_SHLIB: return "SHLIB";
	case PT_PHDR: return "PHDR";
	case PT_TLS: return "TLS";
	case PT_NUM: return "NUM";
	case PT_LOOS: return "LOOS";
	case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
	case PT_GNU_STACK: return "GNU_STACK";
	case PT_GNU_RELRO: return "GNU_RELRO";
#ifdef PT_GNU_PROPERTY
	case PT_GNU_PROPERTY: return "GNU_PROPERTY";
#endif
#ifdef PT_GNU_SFRAME
	case PT_GNU_SFRAME: return "GNU_SFRAME";
#endif
	/* same as PT_SUNWBSS */
	case PT_LOSUNW: return "LOSUNW";
	case PT_SUNWSTACK: return "SUNWSTACK";
	/* same ad PT_HISUNW */
	case PT_HIOS: return "HIOS";
	case PT_LOPROC: return "LOPROC";
	case PT_HIPROC: return "HIPROC";
	default: return "UNKNOWN";
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

int print_phdr(FILE *fp, const char *pfx, GElf_Phdr *pphdr, bool first)
{
	const char *prefix = pfx ?: "";

	if (first) {
		fprintf(fp, "%s  %-16s %-18s %-18s %-16s\n",
			prefix, "Type", "Offset", "VirtAddr", "PhysAddr");
		fprintf(fp, "%s  %-16s %-18s %-18s %-8s %-8s\n",
			prefix, "", "FileSize", "MemSize", "Flags", "Align");
	}
	fprintf(fp, "%s  %-16s %#018lx %#018lx %016lx\n",
		prefix,
		phdr_type_str(pphdr),
		pphdr->p_offset,
		pphdr->p_vaddr,
		pphdr->p_paddr);
	fprintf(fp, "%s  %-16s %#018lx %#018lx %-8s %08lx\n",
		prefix,
		"",
		pphdr->p_filesz,
		pphdr->p_memsz,
		phdr_flags_str_unsafe(pphdr),
		pphdr->p_align);

	return 0;
}

int handle_phdrs(struct elf_file *elf)
{
	int i;

	for (i = 0; i < elf->phdrnum; i++) {
		GElf_Phdr *phdr = &elf->phdrs[i];

		switch (phdr->p_type) {
		case PT_INTERP:
			elf->elf_interpreter = elf->rawfile + phdr->p_offset;
			ulp_debug("[Requesting program interpreter: %s]\n",
				elf->elf_interpreter);
			break;
		case PT_LOAD:
			ulp_debug("get a PT_LOAD program header.\n");
			break;
		default:
			break;
		}
	}

	return 0;
}

