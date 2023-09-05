// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#pragma once

#include <gelf.h>
#include <sys/types.h>

#include <utils/rbtree.h>
#include <utils/list.h>
#include <utils/util.h>

#ifdef __cplusplus
extern "C" {
#endif

struct elf_file {
	int fd;
	Elf *elf;
	char *rawfile;
	size_t rawsize;
	size_t size;
	char filepath[MAX_PATH];
	char *build_id;

	/* ELF file header */
	GElf_Ehdr *ehdr;

	/* Program header */
	size_t phdrnum;
	GElf_Phdr *phdrs;
	const char *elf_interpreter;

	/* Section header */
	size_t shdrnum;
	size_t shdrstrndx;
	GElf_Shdr *shdrs;
	char **shdrnames;

	/**
	 * Useful section header index in "shdrs[]".
	 *
	 * for example:
	 *  GElf_Shdr *dynsym_shdr = elf->shdrs[elf->dynsym];
	 */
	GElf_Word dynsym_shdr_idx;	// SHT_DYNSYM
	GElf_Word symtab_shdr_idx;	// SHT_SYMTAB
	GElf_Word plt_shdr_idx;		// SHT_PROGBITS, .plt
	GElf_Word got_shdr_idx;		// SHT_PROGBITS, .got

	Elf_Data *dynsym_data;
	Elf_Data *symtab_data;
	Elf_Data *plt_data;
	Elf_Data *got_data;
	Elf_Data *versym_data;
	Elf_Data *verneed_data;
	Elf_Data *verdef_data;
	Elf_Data *xndx_data;
	GElf_Word verneed_stridx;
	GElf_Word verdef_stridx;

	/* save all symbol for fast search
	 * struct symbol.node
	 */
	struct rb_root symbols;

	/* has fentry, mcount(), etc. */
	bool support_ftrace;

	/* List all elf files */
	struct list_head node;
};

struct vma_struct;

struct symbol {
	/* strdup() */
	char *name;
	GElf_Sym sym;

	/* Maybe belongs to a VMA */
	struct vma_struct *vma;
	/**
	 * ROOT is one of the following:
	 * struct elf_file.symbols
	 * struct task.vma_symbols
	 */
	struct rb_node node;
};

struct elf_iter {
	size_t i;
	size_t nr;

	union {
		GElf_Phdr *phdr; // point to elf_file.phdrs[]
		GElf_Shdr *shdr; // point to elf_file.shdrs[]
		GElf_Nhdr nhdr;
		GElf_Sym sym;
		GElf_Dyn dyn;
		GElf_Rel rel;
		GElf_Rela rela;
	};

	void *note_name;
	void *note_desc;

	/* private hidden */
	int type;
	size_t str_idx;
	Elf_Scn *scn;
	Elf_Data *data;
};


extern struct list_head client_list;

#ifdef __cplusplus
}
#endif

