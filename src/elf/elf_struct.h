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
	size_t size;
	char filepath[MAX_PATH];
	char *build_id;

	/* ELF file header */
	GElf_Ehdr *ehdr;

	/* Program header */
	size_t phdrnum;
	GElf_Phdr *phdrs;

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

	Elf_Data *dynsym_data;
	Elf_Data *symtab_data;
	Elf_Data *versym_data;
	Elf_Data *verneed_data;
	Elf_Data *verdef_data;
	Elf_Data *xndx_data;
	GElf_Word verneed_stridx;
	GElf_Word verdef_stridx;

	/* List all elf files */
	struct list_head node;
};

extern struct list_head client_list;
extern unsigned int nr_clients;

#ifdef __cplusplus
}
#endif

