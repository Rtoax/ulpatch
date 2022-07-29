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

	Elf_Data *dynsym_data;
	Elf_Data *symtab_data;
	Elf_Data *versym_data;
	Elf_Data *verneed_data;
	Elf_Data *verdef_data;
	Elf_Data *xndx_data;
	GElf_Word verneed_stridx;
	GElf_Word verdef_stridx;

	// has fentry, mcount(), etc.
	bool support_ftrace;

	/* List all elf files */
	struct list_head node;
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
extern unsigned int nr_clients;

#ifdef __cplusplus
}
#endif

