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
	unsigned int dynsym_shdr_idx;	// SHT_DYNSYM


	/* List all elf files */
	struct list_head node;
};

extern struct list_head client_list;

#ifdef __cplusplus
}
#endif

