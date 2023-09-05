// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <utils/util.h>
#include <utils/log.h>
#include <utils/task.h>
#include <utils/compiler.h>
#include <patch/patch.h>

#include <elf/elf_api.h>


int apply_relocate_add(const struct load_info *info, GElf_Shdr *sechdrs,
	const char *strtab, unsigned int symindex, unsigned int relsec)
{
	unsigned int i;

	/**
	 * Object file is indicated by '#', address space is represented by '|--|'
	 *
	 *                                     hdr
	 *                                     |
	 * HostTask    |-----------------------###########----------|
	 *                                     |    ^
	 *                      |<-- t_off  -->|    sh_addr
	 *                      |
	 * TargetTask  |--------###########-------------------------|
	 *                      |    ^
	 *              target_hdr   |
	 *                          rel
	 */
	long t_off = (long)info->hdr - (long)info->target_hdr;

	void *(*write_func)(void *, const void *, size_t) = memcpy;

	/* sh_addr now point to target process address space, so need to relocate
	 * to current process. */
	Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr + t_off;
	Elf64_Sym *sym;
	void *loc;
	uint64_t val;

	ldebug("Applying relocate section %u to %u\n",
		relsec, sechdrs[relsec].sh_info);

	memshowinlog(LOG_INFO, rel, sechdrs[relsec].sh_size);

	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {

		/* This is where to make the change, so, here need to relocate to
		 * current process address space (use info->target_hdr and info->hdr)
		 */
		loc = (void *)(sechdrs[sechdrs[relsec].sh_info].sh_addr + t_off
			+ rel[i].r_offset);

		/* This is the symbol it is referring to.  Note that all
		 * undefined symbols have been resolved.
		 */
		sym = (Elf64_Sym *)(sechdrs[symindex].sh_addr + t_off
			+ ELF64_R_SYM(rel[i].r_info));

		ldebug("type %d st_value %Lx r_addend %Lx loc %Lx\n",
			(int)ELF64_R_TYPE(rel[i].r_info),
			sym->st_value, rel[i].r_addend, (uint64_t)loc);

		val = sym->st_value + rel[i].r_addend;

		/* HOWTO relocate
		 * ref: https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/6n33n7fct/index.html
		 */
		switch (ELF64_R_TYPE(rel[i].r_info)) {

		case R_X86_64_NONE:
			break;

		case R_X86_64_64:
			if (*(uint64_t*)loc != 0)
				goto invalid_relocation;
			write_func(loc, &val, 8);
			break;

		case R_X86_64_32:
			if (*(uint32_t *)loc != 0)
				goto invalid_relocation;
			write_func(loc, &val, 4);
			if (val != *(uint32_t *)loc)
				goto overflow;
			break;

		case R_X86_64_32S:
			if (*(int32_t *)loc != 0)
				goto invalid_relocation;
			write_func(loc, &val, 4);
			if ((int64_t)val != *(int32_t *)loc)
				goto overflow;
			break;

		/* FIXME: Newest kernel already remove {GOTTPOFF, GOTPCREL,
		 * REX_GOTPCRELX, GOTPCRELX} cases */
		case R_X86_64_GOTTPOFF:
		case R_X86_64_GOTPCREL:
		case R_X86_64_REX_GOTPCRELX:
		case R_X86_64_GOTPCRELX:
			if (is_undef_symbol(sym)) {
				// TODO
				// val += sizeof(unsigned long);
			} else if (GELF_ST_TYPE(sym->st_info) == STT_TLS) {
				/* This is GOTTPOFF that already points to an appropriate GOT
				 * entry in the target's memory.
				 */
				val = rel->r_addend + info->target_hdr - 4;
			}
			FALLTHROUGH;

		case R_X86_64_PC32:
		case R_X86_64_PLT32:
			if (*(uint32_t *)loc != 0)
				goto invalid_relocation;
			val -= (uint64_t)loc;
			write_func(loc, &val, 4);
			break;

		case R_X86_64_PC64:
			if (*(uint64_t *)loc != 0)
				goto invalid_relocation;
			val -= (uint64_t)loc;
			write_func(loc, &val, 8);
			break;

		/* FIXME: Newest kernel already remove {TPOFF64, TPOFF32} cases */
		case R_X86_64_TPOFF64:
		case R_X86_64_TPOFF32:
			lerror("TPOFF32/TPOFF64 should not be present\n");
			break;

		default:
			lerror("Unknown rela relocation: %llu\n",
					ELF64_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
	}

	return 0;

invalid_relocation:
	lerror(
		"x86: Skipping invalid relocation target, "
		"existing value is nonzero for type %d, loc %p, val %Lx\n",
		(int)ELF64_R_TYPE(rel[i].r_info), loc, val);

	return -ENOEXEC;

overflow:
	lerror("overflow in relocation type %d val %Lx\n",
		(int)ELF64_R_TYPE(rel[i].r_info), val);
	lerror("likely not compiled with -mcmodel=kernel.\n");
	return -ENOEXEC;
}

