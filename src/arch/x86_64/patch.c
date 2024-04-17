// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
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


const char *ulpatch_jmpq_replace(union text_poke_insn *insn, unsigned long ip,
				 unsigned long addr)
{
	return text_gen_insn(insn, INST_JMPQ, (void *)ip, (void *)addr);
}

static long target_off = 0L;
static inline void *debug_memcpy(void *dst, const void *src, size_t n)
{
	int i;
	ldebug("RELA: Copy %ld bytes from %p to %p\n", n, src, dst);
	ldebug("RELA: Copy %x to %p\n", *(int *)src, dst - target_off);
	if (get_log_level() >= LOG_NOTICE) {
		for (i = 0; i < n; i += sizeof(unsigned int)) {
			unsigned int ui = *(unsigned int *)(src + i);
			ldebug("    : %x\n", ui);
		}
	}

	return memcpy(dst, src, n);
}

int apply_relocate_add(const struct load_info *info, GElf_Shdr *sechdrs,
		       const char *strtab, unsigned int symindex,
		       unsigned int relsec)
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

	target_off = t_off;
	void *(*write_func)(void *, const void *, size_t) = debug_memcpy;

	/**
	 * sh_addr now point to target process address space, so need to
	 * relocate to current process.
	 */
	Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr + t_off;
	Elf64_Sym *sym;
	void *loc;
	uint64_t val;
	int r_type = 0;

	ldebug("Applying relocate section %u to %u\n", relsec, sechdrs[relsec].sh_info);

	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {

		/**
		 * This is where to make the change, so, here need to relocate
		 * to current process address space (use info->target_hdr and
		 * info->hdr)
		 */
		loc = (void *)(sechdrs[sechdrs[relsec].sh_info].sh_addr + t_off
			+ rel[i].r_offset);

		/**
		 * This is the symbol it is referring to.  Note that all
		 * undefined symbols have been resolved.
		 */
		sym = (Elf64_Sym *)(sechdrs[symindex].sh_addr + t_off)
			+ ELF64_R_SYM(rel[i].r_info);

		const char *symname = strtab + sym->st_name;
		r_type = (int)ELF64_R_TYPE(rel[i].r_info);
		val = sym->st_value + rel[i].r_addend;

		ldebug("RELA: %s, st_name %d, type %d, st_value %lx, "
		       "r_addend %lx, loc %lx, val %lx\n",
			symname, sym->st_name, r_type,
			sym->st_value, rel[i].r_addend, (uint64_t)loc, val);

		switch (r_type) {

		case R_X86_64_NONE:
			lwarning("Handle R_X86_64_NONE\n");
			break;

		case R_X86_64_64:
			lwarning("Handle R_X86_64_64\n");
			if (*(uint64_t*)loc != 0)
				goto invalid_relocation;
			write_func(loc, &val, 8);
			break;

		case R_X86_64_32:
			lwarning("Handle R_X86_64_32\n");
			if (*(uint32_t *)loc != 0)
				goto invalid_relocation;
			write_func(loc, &val, 4);
			if (val != *(uint32_t *)loc) {
				lerror("R_X86_64_32 overflow val(%lx) != loc(%x)\n",
					val, *(uint32_t *)loc);
				goto overflow;
			}
			break;

		case R_X86_64_32S:
			lwarning("Handle R_X86_64_32S\n");
			if (*(int32_t *)loc != 0)
				goto invalid_relocation;
			write_func(loc, &val, 4);
			if ((int64_t)val != *(int32_t *)loc)
				goto overflow;
			break;

		/**
		 * FIXME: Newest kernel already remove {GOTTPOFF, GOTPCREL,
		 * REX_GOTPCRELX, GOTPCRELX} cases
		 */
		case R_X86_64_GOTTPOFF:
		case R_X86_64_GOTPCREL:
		case R_X86_64_REX_GOTPCRELX:
		case R_X86_64_GOTPCRELX:
			if (is_undef_symbol(sym)) {
				// TODO
				// val += sizeof(unsigned long);
			} else if (GELF_ST_TYPE(sym->st_info) == STT_TLS) {
				/**
				 * This is GOTTPOFF that already points to an
				 * appropriate GOT entry in the target's memory.
				 */
				val = rel->r_addend + info->target_hdr - 4;
			}
			FALLTHROUGH;

		case R_X86_64_PC32:
			lwarning("Handle R_X86_64_PC32\n");
		case R_X86_64_PLT32:
			lwarning("Handle R_X86_64_PLT32\n");
			if (*(uint32_t *)loc != 0)
				goto invalid_relocation;
			/**
			 * - t_off means that in target process
			 */
			val -= (uint64_t)loc - t_off;
			write_func(loc, &val, 4);
			break;

		case R_X86_64_PC64:
			lwarning("Handle R_X86_64_PC64\n");
			if (*(uint64_t *)loc != 0)
				goto invalid_relocation;
			/**
			 * - t_off means that in target process
			 */
			val -= (uint64_t)loc - t_off;
			write_func(loc, &val, 8);
			break;

		/* FIXME: Newest kernel already remove {TPOFF64, TPOFF32} cases */
		case R_X86_64_TPOFF64:
		case R_X86_64_TPOFF32:
			lerror("TPOFF32/TPOFF64 should not be present\n");
			break;

		default:
			lerror("Unknown rela relocation: %s\n",
				rela_type_string(r_type));
			return -ENOEXEC;
		}
	}

	return 0;

invalid_relocation:
	lerror("x86: Skipping invalid relocation target, "
		"existing value is nonzero for type %s(%d), loc %p, val %lx\n",
		rela_type_string(r_type), r_type, loc, val);
	return -ENOEXEC;

overflow:
	lerror("overflow in relocation type %s(%d) val %lx\n",
		rela_type_string(r_type), r_type, val);
	lerror("likely not compiled with -fpic and -fno-PIE.\n");
	return -ENOEXEC;
}

