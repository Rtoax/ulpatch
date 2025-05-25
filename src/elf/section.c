// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "elf/elf-api.h"
#include "utils/log.h"
#include "utils/list.h"
#include "utils/compiler.h"


int handle_sections(struct elf_file *elf)
{
	int i, ret = 0;

	for (i = 0; i < elf->shdrnum; i++) {
		GElf_Shdr *shdr = &elf->shdrs[i];
		Elf_Scn *scn = elf_getscn(elf->elf, i);

		elf->shdrnames[i] = elf_strptr(elf->elf, elf->shdrstrndx,
						shdr->sh_name);
		if (elf->shdrnames[i] == NULL) {
			ulp_error("couldn't get section name: %s\n", elf_errmsg(-1));
			return -ENOENT;
		}

		/* Handle section header by type */
		switch (shdr->sh_type) {
		case SHT_PROGBITS:
			/* .plt */
			if (strcmp(elf->shdrnames[i], ".plt") == 0) {
				ulp_debug("%s PLT: %d\n", elf->filepath, i);
				elf->plt_data = elf_getdata(scn, NULL);
				elf->plt_shdr_idx = i;
			/* .got */
			} else if (strcmp(elf->shdrnames[i], ".got") == 0) {
				ulp_debug("%s GOT: %d\n", elf->filepath, i);
				elf->got_data = elf_getdata(scn, NULL);
				elf->got_shdr_idx = i;
			}
			break;
		case SHT_SYMTAB:
			elf->symtab_data = elf_getdata(scn, NULL);
			elf->symtab_shdr_idx = i;
			break;
		/**
		 * Symbols import from dynamic library.
		 */
		case SHT_DYNSYM:
			elf->dynsym_data = elf_getdata(scn, NULL);
			elf->dynsym_shdr_idx = i;
			break;
		case SHT_NOTE:
			handle_notes(elf, shdr, scn);
			break;
		case SHT_REL:
		case SHT_RELA:
			handle_relocs(elf, shdr, scn);
			break;
		case SHT_GNU_ATTRIBUTES:
		case SHT_GNU_LIBLIST:
		/* readelf --section-groups */
		case SHT_GROUP:
		default:
			break;
		}

		/* Find out whether we have other sections we might need.  */
		Elf_Scn *runscn = NULL;

		while ((runscn = elf_nextscn(elf->elf, runscn)) != NULL) {
			GElf_Shdr runshdr_mem;
			GElf_Shdr *runshdr = gelf_getshdr(runscn, &runshdr_mem);
			if (!runshdr)
				continue;

			/* Handle section header by type */
			switch (runshdr->sh_type) {
			/* Bingo, found the version information. Now get the data. */
			case SHT_GNU_versym:
				if (runshdr->sh_link == elf_ndxscn(scn))
					elf->versym_data = elf_getdata(runscn, NULL);
				break;
			/* This is the information about the needed versions. */
			case SHT_GNU_verneed:
				elf->verneed_data = elf_getdata(runscn, NULL);
				elf->verneed_stridx = runshdr->sh_link;
				break;
			/* This is the information about the defined versions. */
			case SHT_GNU_verdef:
				elf->verdef_data = elf_getdata(runscn, NULL);
				elf->verdef_stridx = runshdr->sh_link;
				break;
			/* Extended section index. */
			case SHT_SYMTAB_SHNDX:
				if (runshdr->sh_link == elf_ndxscn(scn))
					elf->xndx_data = elf_getdata(runscn, NULL);
				break;
			}
		}
	}

	if (elf->symtab_shdr_idx)
		handle_symtab(elf, elf_getscn(elf->elf, elf->symtab_shdr_idx));

	if (elf->dynsym_shdr_idx)
		handle_symtab(elf, elf_getscn(elf->elf, elf->dynsym_shdr_idx));

	return ret;
}

