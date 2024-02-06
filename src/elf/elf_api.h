// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#pragma once

#include <stdint.h>
#include <libelf.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <elf/elf_struct.h>
#include <utils/util.h>
#include <utils/compiler.h>


struct file_info {
	file_type type;
	const char *name;
	bool client_select;
	/* If ELF, else = NULL */
	const char *elf_build_id;
};


/* see elfutils/src/readelf.c */
#ifdef __linux__
#define CORE_SIGILL  SIGILL
#define CORE_SIGBUS  SIGBUS
#define CORE_SIGFPE  SIGFPE
#define CORE_SIGSEGV SIGSEGV
#define CORE_SI_USER SI_USER
#else
/* We want the linux version of those as that is what shows up in the core files. */
#define CORE_SIGILL  4  /* Illegal instruction (ANSI).  */
#define CORE_SIGBUS  7  /* BUS error (4.2 BSD).  */
#define CORE_SIGFPE  8  /* Floating-point exception (ANSI).  */
#define CORE_SIGSEGV 11 /* Segmentation violation (ANSI).  */
#define CORE_SI_USER 0  /* Sent by kill, sigsend.  */
#endif


struct elf_file *elf_file_open(const char *filepath);
int elf_file_close(const char *filepath);

/* ELF Ehdr api */
bool ehdr_ok(const GElf_Ehdr *ehdr);
bool ehdr_magic_ok(const GElf_Ehdr *ehdr);
int print_ehdr(FILE *fp, const GElf_Ehdr *ehdr);

/* ELF Phdr api */
int handle_phdrs(struct elf_file *elf);
int print_phdr(FILE *fp, GElf_Phdr *pphdr, bool first);
const char *phdr_flags_str_unsafe(GElf_Phdr *pphdr);
const char *phdr_type_str_unsafe(GElf_Phdr *pphdr);

/* ELF Sections api */
int handle_sections(struct elf_file *elf);

/* ELF Symbol api */
const char *st_bind_string(const GElf_Sym *sym);
const char *st_type_string(const GElf_Sym *sym);

GElf_Sym *get_next_symbol(struct elf_file *elf, Elf_Scn *scn,
	int isym, size_t *nsyms,
	GElf_Sym *sym_mem, char **symname, char **pversion);

/**
 * for_each_symbol - For each symbol in elf
 *
 * for example: see also handle_symtab()
 *
 *	size_t nsym = 0, isym = 0;
 *	GElf_Sym __unused *sym, sym_mem;
 *	char *symname, *pversion;
 *
 *	for_each_symbol(elf, scn, sym, sym_mem, isym, nsym, symname, pversion) {
 *		if (!sym) continue;
 *		printf("%s%s%s\n", symname, pversion?"@":"", pversion?:"");
 *	}
 *
 */
#define for_each_symbol(elf, scn, sym, sym_mem, isym, nsym, symname, pversion) \
	for (	\
		isym = 0, sym = get_next_symbol(elf, scn, isym, &nsym,	\
			&sym_mem, &symname, &pversion);	\
		isym < nsym;	\
		isym++, sym = get_next_symbol(elf, scn, isym, &nsym,	\
			&sym_mem, &symname, &pversion)	\
	)

int handle_symtab(struct elf_file *elf, Elf_Scn *scn);

struct symbol *alloc_symbol(const char *name, const GElf_Sym *sym);
void free_symbol(struct symbol *s);
int link_symbol(struct elf_file *elf, struct symbol *s);
struct symbol *find_symbol(struct elf_file *elf, const char *name);
int cmp_symbol_name(struct rb_node *n1, unsigned long key);

/**
 * stderr@GLIBC_2.2.5
 * symname = stderr
 * vername = GLIBC_2.2.5
 */
int print_sym(const GElf_Sym *sym, const char *symname, const char *vername);
int is_undef_symbol(const GElf_Sym *sym);

/* ELF Note api */
int handle_notes(struct elf_file *elf, GElf_Shdr *shdr, Elf_Scn *scn);
int print_elf_build_id(FILE *fp, uint8_t *build_id, size_t descsz);
const char *strbuildid(uint8_t *bid, size_t descsz, char *buf, size_t buf_len);

/* ELF Rela api */
int handle_relocs(struct elf_file *elf, GElf_Shdr *shdr, Elf_Scn *scn);

/* ELF Auxv api */
int auxv_type_info(GElf_Xword a_type, const char **name, const char **format);

