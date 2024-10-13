// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#pragma once

#include <stdint.h>
#include <libelf.h>
#include <stdbool.h>
#include <signal.h>
#include <gelf.h>
#include <bfd.h>
#include <sys/types.h>

#include <utils/util.h>
#include <utils/compiler.h>
#include <utils/rbtree.h>
#include <utils/list.h>

struct elf_file {
	int fd;
	Elf *elf;
	char *rawfile;
	size_t rawsize;
	size_t size;
	char filepath[PATH_MAX];
#define NO_BUILD_ID	"No Build ID"
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

	/**
	 * Save all symbol for fast search
	 * struct symbol.node
	 */
	struct rb_root symbols;

	/* has fentry, mcount(), etc. */
	bool support_ftrace;
	char *mcount_name;

	/* List all elf files */
	struct list_head node;
};

struct vm_area_struct;

enum sym_type {
	SYM_TYPE_MIN,
	/**
	 * This symbol is extern, check with is_extern_symbol(), of course it's
	 * undef, but undef symbol maybe not extern, like @plt
	 */
	SYM_TYPE_EXTERN,
	/**
	 * If symbol is undef and not extern.
	 */
	SYM_TYPE_UNDEF,
	/**
	 * Defined symbol.
	 */
	SYM_TYPE_DEFINED,
	SYM_TYPE_MAX,
};

struct symbol {
	/* strdup() */
	char *name;
	/**
	 * Store GELF_ST_TYPE(sym->st_info), such as STT_OBJECT/STT_FUNC
	 * for rbtree compare and search.
	 *
	 * FIXME: This field is not useful right now.
	 */
	int type;

	/**
	 * Mark the symbol type.
	 */
	enum sym_type sym_type;

	GElf_Sym sym;

	/**
	 * If symbol from ELF file, point to elf file phdrs. If symbol from
	 * VMA mem, point to vma's elf phdrs, and used to locate VMA.
	 */
	int nphdrs;
	GElf_Phdr *phdrs;

	/**
	 * Maybe belongs to a VMA, and this vma is ELF format, which is the
	 * leader of all other PT_LOAD vmas.
	 *
	 * FIXME: If symbol from ELF file, we could found the vma by match
	 * the program header, the point it to right vma.
	 */
	struct vm_area_struct *vma;

	/**
	 * ROOT is one of the following:
	 * struct elf_file.symbols
	 */
	struct rb_node node;
};


int elf_core_init(void);
const char *libc_object(void);

struct elf_file *elf_file_open(const char *filepath);
struct elf_file *elf_file_find(const char *filepath);
int elf_file_close(const char *filepath);

/* ELF Ehdr api */
bool ehdr_ok(const GElf_Ehdr *ehdr);
bool ehdr_magic_ok(const GElf_Ehdr *ehdr);
int print_ehdr(FILE *fp, const GElf_Ehdr *ehdr);

/* ELF Phdr api */
int handle_phdrs(struct elf_file *elf);
int print_phdr(FILE *fp, const char *pfx, GElf_Phdr *pphdr, bool first);
const char *phdr_flags_str_unsafe(GElf_Phdr *pphdr);
const char *phdr_type_str(GElf_Phdr *pphdr);

/* ELF Sections api */
int handle_sections(struct elf_file *elf);

/* ELF Symbol api */
const char *st_bind_string(const GElf_Sym *sym);
const char *st_type_string(const GElf_Sym *sym);
const char *i_st_type_string(const int type);

GElf_Sym *get_next_symbol(struct elf_file *elf, Elf_Scn *scn,
	int isym, size_t *nsyms,
	GElf_Sym *sym_mem, char **symname, char **pversion);

int handle_symtab(struct elf_file *elf, Elf_Scn *scn);

struct symbol *alloc_symbol(const char *name, const GElf_Sym *sym);
struct symbol *dup_symbol(struct symbol *sym);
void free_symbol(struct symbol *s);
void rb_free_symbol(struct rb_node *node);
int link_symbol(struct elf_file *elf, struct symbol *s);
struct symbol *find_symbol(struct elf_file *elf, const char *name, int type);
struct symbol *find_extern_symbol(struct elf_file *elf, const char *name,
				  int type);
struct symbol *find_undef_symbol(struct elf_file *elf, const char *name,
				 int type);
int for_each_symbol(struct elf_file *elf, void (*handler)(struct elf_file *,
							  struct symbol *,
							  void *),
		    void *arg);
int cmp_symbol_name(struct rb_node *n1, unsigned long key);
int fprint_symbol(FILE *fp, const char *pfx, struct symbol *s, int firstline);
bool elf_support_ftrace(struct elf_file *elf);
const char *elf_mcount_name(struct elf_file *elf);

int fprint_sym(FILE *fp, const char *pfx, const GElf_Sym *sym,
	       const char *symname, const char *vername, bool firstline);
int is_undef_symbol(const GElf_Sym *sym);
bool is_extern_symbol(const GElf_Sym *sym);
bool is_ftrace_entry(char *func);

/* ELF Note api */
int handle_notes(struct elf_file *elf, GElf_Shdr *shdr, Elf_Scn *scn);
int print_elf_build_id(FILE *fp, uint8_t *build_id, size_t descsz);
const char *elf_strbuildid(uint8_t *bid, size_t descsz, char *buf,
			   size_t buf_len);

/* ELF Rela api */
int handle_relocs(struct elf_file *elf, GElf_Shdr *shdr, Elf_Scn *scn);
const char *r_x86_64_name(int r);
const char *r_aarch64_name(int r);
const char *rela_type_string(int r);
void print_rela(GElf_Rela *rela);

/* ELF Auxv api */
int auxv_type_info(GElf_Xword a_type, const char **name, const char **format);

/* Swap 'objdump' command to C code. */
struct bfd_elf_file;
struct bfd_sym;

struct bfd_elf_file* bfd_elf_open(const char *elf_file);
int bfd_elf_file_refcount(struct bfd_elf_file *file);
const char *bfd_elf_file_name(struct bfd_elf_file *file);
int bfd_elf_close(struct bfd_elf_file *file);

unsigned long bfd_elf_plt_sym_addr(struct bfd_elf_file *file, const char *sym);
struct bfd_sym *bfd_next_plt_sym(struct bfd_elf_file *file,
				 struct bfd_sym *prev);
unsigned long bfd_elf_text_sym_addr(struct bfd_elf_file *file, const char *name);
struct bfd_sym *bfd_next_text_sym(struct bfd_elf_file *file,
				  struct bfd_sym *prev);
unsigned long bfd_elf_data_sym_addr(struct bfd_elf_file *file, const char *name);
struct bfd_sym *bfd_next_data_sym(struct bfd_elf_file *file,
				  struct bfd_sym *prev);

unsigned long bfd_sym_addr(struct bfd_sym *symbol);
const char *bfd_sym_name(struct bfd_sym *symbol);

const struct bfd_build_id *bfd_elf_bid(struct bfd_elf_file *file);
const char *bfd_strbid(const struct bfd_build_id *bid, char *buf, int blen);

int bfd_elf_destroy(void);

/**
 * Store BFD function wrapper here
 */
#ifdef BINUTILS_HAVE_BFD_SECTION_NAME
# define ulp_bfd_section_name(sec)	bfd_section_name(sec)
#elif defined(BINUTILS_HAVE_BFD_SECTION_NAME2)
# define ulp_bfd_section_name(sec)	bfd_section_name(bfd, sec)
#else
# define ulp_bfd_section_name(sec)	sec->name
#endif
