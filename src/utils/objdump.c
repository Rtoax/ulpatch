// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <stdio.h>
#include <malloc.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <elf/elf_api.h>

#ifdef HAVE_BINUTILS_BFD_H
#include <bfd.h>
#else
#error "Must install binutils-devel"
#endif

#include "log.h"
#include "util.h"
#include "list.h"


enum sym_type {
	S_T_PLT, /* @plt */
	S_T_NUM,
};

struct objdump_elf_file {
	char name[PATH_MAX];

	bfd *bfd;

	asymbol **syms;
	long symcount;

	asymbol **dynsyms;
	long dynsymcount;

	asymbol *synthsyms;
	long synthcount;

	asymbol **sorted_syms;
	long sorted_symcount;

	/* head is file_list */
	struct list_head node;

	struct rb_root rb_tree_syms[S_T_NUM];
};

struct objdump_symbol {
	char *name;
	unsigned long addr;
	enum sym_type type;

	/* root is objdump_elf_file.rb_tree_syms[type] */
	struct rb_node node;
};

/* We just open few elf files, link list is ok. */
static LIST_HEAD(file_list);


static struct objdump_elf_file* file_already_load(const char *filename)
{
	struct objdump_elf_file *f, *tmp, *ret = NULL;

	list_for_each_entry_safe(f, tmp, &file_list, node) {
		if (!strcmp(filename, f->name)) {
			ret = f;
			break;
		}
	}
	return ret;
}

/* the @key is (unsigned long)objdump_elf_file */
static inline int cmp_sym(struct rb_node *n1, unsigned long key)
{
	struct objdump_symbol *s1 = rb_entry(n1, struct objdump_symbol, node);
	struct objdump_symbol *s2 = (struct objdump_symbol*)key;

	return strcmp(s1->name, s2->name);
}

static struct objdump_symbol *alloc_sym(const char *name, unsigned long addr,
					enum sym_type type)
{
	struct objdump_symbol *s = malloc(sizeof(struct objdump_symbol));

	memset(s, 0, sizeof(*s));

	s->name = strdup(name);
	s->addr = addr;
	s->type = type;

	return s;
}

static void free_sym(struct objdump_symbol *s)
{
	free(s->name);
	free(s);
}

static struct objdump_symbol *find_sym(struct rb_root *root, const char *name)
{
	struct objdump_symbol tmp = {
		.name = (char *)name,
	};
	struct rb_node *node = rb_search_node(root, cmp_sym,
					(unsigned long)&tmp);

	return node ? rb_entry(node, struct objdump_symbol, node) : NULL;
}

/* Insert OK, return 0, else return -1 */
static int link_sym(struct rb_root *root, struct objdump_symbol *s)
{
	struct rb_node *node = rb_insert_node(root, &s->node,
						cmp_sym, (unsigned long)s);
	return node ? -1 : 0;
}

static struct objdump_symbol *next_sym(struct rb_root *root,
				       struct objdump_symbol *prev)
{
	struct rb_node *next;
	next = prev ? rb_next(&prev->node) : rb_first(root);
	return next ? rb_entry(next, struct objdump_symbol, node) : NULL;
}

struct objdump_symbol *objdump_elf_plt_next_symbol(struct objdump_elf_file *file,
						   struct objdump_symbol *prev)
{
	return next_sym(&file->rb_tree_syms[S_T_PLT], prev);
}

unsigned long objdump_symbol_address(struct objdump_symbol *symbol)
{
	return symbol ? symbol->addr : 0;
}

const char* objdump_symbol_name(struct objdump_symbol *symbol)
{
	return symbol ? symbol->name : NULL;
}

unsigned long objdump_elf_plt_symbol_address(struct objdump_elf_file *file,
					     const char *name)
{
	if (!file)
		return 0;

	struct objdump_symbol *symbol;
	struct rb_root *rbroot = &file->rb_tree_syms[S_T_PLT];

	symbol = find_sym(rbroot, name);

	return symbol ? symbol->addr : 0;
}

static asymbol **slurp_symtab(struct objdump_elf_file *file)
{
	bfd *abfd = file->bfd;

	file->symcount = 0;
	if (!(bfd_get_file_flags(abfd) & HAS_SYMS))
		return NULL;

	long storage = bfd_get_symtab_upper_bound(abfd);
	if (storage < 0) {
		lerror("failed to read symbol table from: %s",
			bfd_get_filename(abfd));
	}

	if (storage == 0)
		return NULL;

	asymbol **sy = (asymbol **) malloc(storage);
	file->symcount = bfd_canonicalize_symtab(abfd, sy);
	if (file->symcount < 0)
		lerror("%s: symcount < 0\n", bfd_get_filename(abfd));

	return sy;
}

static asymbol **slurp_dynamic_symtab(struct objdump_elf_file *file)
{
	bfd *abfd = file->bfd;

	file->dynsymcount = 0;
	long storage = bfd_get_dynamic_symtab_upper_bound(abfd);
	if (storage < 0) {
		if (!(bfd_get_file_flags(abfd) & DYNAMIC)) {
			lerror("%s: not a dynamic object", bfd_get_filename(abfd));
			return NULL;
		}

		lerror("%s\n", bfd_get_filename(abfd));
		abort();
	}

	if (storage == 0)
		return NULL;

	asymbol **sy = (asymbol **) malloc(storage);
	file->dynsymcount = bfd_canonicalize_dynamic_symtab(abfd, sy);
	if (file->dynsymcount < 0) {
		lerror("%s\n", bfd_get_filename(abfd));
		abort();
	}

	return sy;
}

static bool asymbol_is_plt(asymbol *sym)
{
	return strstr(sym->name, "@plt") ? true : false;
}

static const char* asymbol_pure_name(asymbol *sym, char *buf, int blen)
{
	char *name = strstr(sym->name, "@");
	if (!name)
		return sym->name;

	unsigned int len = name - sym->name;
	if (len > blen) {
		fprintf(stderr, "Too short buffer length.\n");
		return NULL;
	}

	strncpy(buf, sym->name, len);
	buf[len] = '\0';

	return buf;
}

static inline bool _startswith(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

static bool is_significant_symbol_name(const char * name)
{
	return _startswith(name, ".plt") || _startswith(name, ".got");
}

static long remove_useless_symbols(asymbol **symbols, long count)
{
	asymbol **in_ptr = symbols, **out_ptr = symbols;

	while (--count >= 0) {
		asymbol *sym = *in_ptr++;

		if (sym->name == NULL || sym->name[0] == '\0')
			continue;
		if ((sym->flags & (BSF_DEBUGGING | BSF_SECTION_SYM))
			&& ! is_significant_symbol_name(sym->name))
			continue;
		if (bfd_is_und_section(sym->section)
			|| bfd_is_com_section(sym->section))
			continue;

		*out_ptr++ = sym;
	}
	return out_ptr - symbols;
}

static void disassemble_data(struct objdump_elf_file *file)
{
	int i;

	file->sorted_symcount = file->symcount ? file->symcount : file->dynsymcount;
	file->sorted_syms = (asymbol **) malloc((file->sorted_symcount + file->synthcount)
						* sizeof(asymbol *));

	if (file->sorted_symcount != 0) {
		memcpy(file->sorted_syms, file->symcount ? file->syms : file->dynsyms,
			file->sorted_symcount * sizeof(asymbol *));

		file->sorted_symcount = remove_useless_symbols(file->sorted_syms,
							file->sorted_symcount);
	}

	for (i = 0; i < file->synthcount; ++i) {
		file->sorted_syms[file->sorted_symcount] = file->synthsyms + i;
		++file->sorted_symcount;
	}

	for (i = 0; i < file->sorted_symcount; i++) {
		asymbol *s = file->sorted_syms[i];
		char buf[256];
		const char *name = asymbol_pure_name(s, buf, sizeof(buf));

		ldebug("SYM: %#016lx  %s %s\n", bfd_asymbol_value(s),
			name, asymbol_is_plt(s) ? "PLT" : "");

		if (asymbol_is_plt(s)) {
			struct objdump_symbol *symbol;
			symbol = alloc_sym(name, bfd_asymbol_value(s), S_T_PLT);
			link_sym(&file->rb_tree_syms[S_T_PLT], symbol);
		}
	}

	free(file->sorted_syms);
}

static void dump_bfd(struct objdump_elf_file *file)
{
	file->syms = slurp_symtab(file);
	file->dynsyms = slurp_dynamic_symtab(file);

	file->synthcount = bfd_get_synthetic_symtab(file->bfd, file->symcount,
					file->syms, file->dynsymcount, file->dynsyms,
					&file->synthsyms);
	if (file->synthcount < 0)
		file->synthcount = 0;

	disassemble_data(file);

	if (file->syms) {
		free(file->syms);
		file->syms = NULL;
	}
	if (file->dynsyms) {
		free(file->dynsyms);
		file->dynsyms = NULL;
	}

	if (file->synthsyms) {
		free(file->synthsyms);
		file->synthsyms = NULL;
	}
	file->symcount = 0;
	file->dynsymcount = 0;
	file->synthcount = 0;
}

static int objdump_elf_load_plt(struct objdump_elf_file *file)
{
	char **matching;
	char *target = NULL;

	file->bfd = bfd_openr(file->name, target);

	if (bfd_check_format(file->bfd, bfd_archive)) {
		lerror("%s is bfd archive, do nothing, close\n", file->name);
		goto close;
	}

	if (bfd_check_format_matches(file->bfd, bfd_object, &matching)) {
		ldebug("%s is bfd_object.\n", file->name);
		dump_bfd(file);
	}

close:
	bfd_close(file->bfd);

	return 0;
}


static struct objdump_elf_file* file_load(const char *filename)
{
	int i;
	struct objdump_elf_file *file;

	file = malloc(sizeof(struct objdump_elf_file));
	memset(file, 0, sizeof(struct objdump_elf_file));

	strncpy(file->name, filename, PATH_MAX - 1);

	for (i = 0; i < S_T_PLT; i++)
		rb_init(&file->rb_tree_syms[i]);

	objdump_elf_load_plt(file);

	list_add(&file->node, &file_list);

	return file;
}

struct objdump_elf_file* objdump_elf_load(const char *elf_file)
{
	struct objdump_elf_file *file = NULL;

	if (!fexist(elf_file)) {
		errno = -EEXIST;
		return NULL;
	}

	file = file_already_load(elf_file);
	if (!file)
		file = file_load(elf_file);

	return file;
}

int objdump_elf_close(struct objdump_elf_file *file)
{
	if (!file)
		return -1;

	list_del(&file->node);
	free(file);

	return 0;
}

static void __rb_free_sym(struct rb_node *node)
{
	struct objdump_symbol *s = rb_entry(node, struct objdump_symbol, node);
	free_sym(s);
}

int objdump_destroy(void)
{
	struct objdump_elf_file *f, *tmp;

	list_for_each_entry_safe(f, tmp, &file_list, node) {
		int i;

		list_del(&f->node);

		/* Destroy all type symbols rb tree */
		for (i = 0; i < S_T_NUM; i++)
			rb_destroy(&f->rb_tree_syms[i], __rb_free_sym);

		free(f);
	}

	return 0;
}

