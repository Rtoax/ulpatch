// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdio.h>
#include <malloc.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <bfd.h>

#include <elf/elf-api.h>

#include <utils/log.h>
#include <utils/util.h>
#include <utils/list.h>


enum obj_sym_type {
	S_T_PLT, /* @plt */
	S_T_NUM,
};

struct bfd_elf_file {
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

struct bfd_sym {
	char *name;
	unsigned long addr;
	enum obj_sym_type type;

	/* root is bfd_elf_file.rb_tree_syms[type] */
	struct rb_node node;
};

/* We just open few elf files, link list is ok. */
static LIST_HEAD(file_list);


static struct bfd_elf_file* file_already_load(const char *filename)
{
	struct bfd_elf_file *f, *tmp, *ret = NULL;

	list_for_each_entry_safe(f, tmp, &file_list, node) {
		if (!strcmp(filename, f->name)) {
			ret = f;
			break;
		}
	}
	return ret;
}

/* the @key is (unsigned long)bfd_sym */
static inline int cmp_sym(struct rb_node *n1, unsigned long key)
{
	struct bfd_sym *s1 = rb_entry(n1, struct bfd_sym, node);
	struct bfd_sym *s2 = (struct bfd_sym *)key;

	return strcmp(s1->name, s2->name);
}

static struct bfd_sym *alloc_bfd_sym(const char *name, unsigned long addr,
				     enum obj_sym_type type)
{
	struct bfd_sym *s = malloc(sizeof(struct bfd_sym));

	memset(s, 0, sizeof(*s));

	s->name = strdup(name);
	s->addr = addr;
	s->type = type;

	return s;
}

static void free_sym(struct bfd_sym *s)
{
	free(s->name);
	free(s);
}

static struct bfd_sym *find_bfd_sym(struct rb_root *root, const char *name)
{
	struct bfd_sym tmp = {
		.name = (char *)name,
	};
	struct rb_node *node = rb_search_node(root, cmp_sym,
					(unsigned long)&tmp);

	return node ? rb_entry(node, struct bfd_sym, node) : NULL;
}

/* Insert OK, return 0, else return -1 */
static int link_bfd_sym(struct rb_root *root, struct bfd_sym *s)
{
	struct rb_node *node;
	node = rb_insert_node(root, &s->node, cmp_sym, (unsigned long)s);
	return node ? -1 : 0;
}

static struct bfd_sym *next_bfd_sym(struct rb_root *root, struct bfd_sym *prev)
{
	struct rb_node *next;
	next = prev ? rb_next(&prev->node) : rb_first(root);
	return next ? rb_entry(next, struct bfd_sym, node) : NULL;
}

struct bfd_sym *bfd_next_plt_sym(struct bfd_elf_file *file,
				 struct bfd_sym *prev)
{
	return next_bfd_sym(&file->rb_tree_syms[S_T_PLT], prev);
}

unsigned long bfd_sym_addr(struct bfd_sym *symbol)
{
	return symbol ? symbol->addr : 0;
}

const char *bfd_sym_name(struct bfd_sym *symbol)
{
	return symbol ? symbol->name : NULL;
}

unsigned long bfd_elf_plt_symbol_addr(struct bfd_elf_file *file,
				      const char *name)
{
	if (!file)
		return 0;

	struct bfd_sym *symbol;
	struct rb_root *rbroot = &file->rb_tree_syms[S_T_PLT];

	symbol = find_bfd_sym(rbroot, name);

	return symbol ? symbol->addr : 0;
}

static asymbol **slurp_symtab(struct bfd_elf_file *file)
{
	asymbol **sy;
	bfd *abfd = file->bfd;
	long storage;

	file->symcount = 0;
	if (!(bfd_get_file_flags(abfd) & HAS_SYMS)) {
		errno = ENOENT;
		return NULL;
	}

	storage = bfd_get_symtab_upper_bound(abfd);
	if (storage <= 0) {
		ulp_error("failed to read symbol table from: %s",
			  bfd_get_filename(abfd));
		errno = ENOENT;
		return NULL;
	}

	sy = (asymbol **)malloc(storage);
	file->symcount = bfd_canonicalize_symtab(abfd, sy);
	if (file->symcount < 0) {
		ulp_error("%s: symcount < 0\n", bfd_get_filename(abfd));
		free(sy);
		errno = ENOENT;
		return NULL;
	}

	return sy;
}

static asymbol **slurp_dynamic_symtab(struct bfd_elf_file *file)
{
	long storage;
	asymbol **sy = NULL;
	bfd *abfd = file->bfd;

	file->dynsymcount = 0;

	storage = bfd_get_dynamic_symtab_upper_bound(abfd);
	if (storage <= 0) {
		if (!(bfd_get_file_flags(abfd) & DYNAMIC)) {
			ulp_warning("%s: not a dynamic object", bfd_get_filename(abfd));
			return NULL;
		}

		ulp_error("%s\n", bfd_get_filename(abfd));
		return NULL;
	}

	sy = (asymbol **)malloc(storage);
	file->dynsymcount = bfd_canonicalize_dynamic_symtab(abfd, sy);
	if (file->dynsymcount < 0) {
		ulp_error("%s\n", bfd_get_filename(abfd));
		return NULL;
	}

	return sy;
}

static bool asymbol_is_plt(asymbol *sym)
{
	return strstr(sym->name, "@plt") ? true : false;
}

static const char *asymbol_pure_name(asymbol *sym, char *buf, int blen)
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

static bool is_significant_symbol_name(const char *name)
{
	return ulp_startswith(name, ".plt") || ulp_startswith(name, ".got");
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

static void disassemble_data(struct bfd_elf_file *file)
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

		ulp_debug("SYM: %#016lx  %s %s\n", bfd_asymbol_value(s),
			name, asymbol_is_plt(s) ? "PLT" : "");

		if (asymbol_is_plt(s)) {
			struct bfd_sym *symbol;
			symbol = alloc_bfd_sym(name, bfd_asymbol_value(s), S_T_PLT);
			link_bfd_sym(&file->rb_tree_syms[S_T_PLT], symbol);
		}
	}

	free(file->sorted_syms);
}

static struct bfd_elf_file *file_load(const char *filename)
{
	int i;
	struct bfd_elf_file *file;
	char **matching;
	char *target = NULL;

	file = malloc(sizeof(struct bfd_elf_file));
	memset(file, 0, sizeof(struct bfd_elf_file));

	strncpy(file->name, filename, PATH_MAX - 1);

	for (i = 0; i < S_T_NUM; i++)
		rb_init(&file->rb_tree_syms[i]);

	file->bfd = bfd_openr(file->name, target);

	if (bfd_check_format(file->bfd, bfd_archive)) {
		ulp_error("%s is bfd archive, do nothing, close\n", file->name);
		goto close;
	}

	if (!bfd_check_format_matches(file->bfd, bfd_object, &matching)) {
		ulp_error("%s is not bfd_object.\n", file->name);
		goto close;
	}

	file->syms = slurp_symtab(file);
	file->dynsyms = slurp_dynamic_symtab(file);

	file->synthcount = bfd_get_synthetic_symtab(file->bfd,
					     file->symcount, file->syms,
					     file->dynsymcount, file->dynsyms,
					     &file->synthsyms);
	if (file->synthcount < 0)
		file->synthcount = 0;

	disassemble_data(file);

	list_add(&file->node, &file_list);

	return file;

close:
	bfd_close(file->bfd);
	return NULL;
}

struct bfd_elf_file *bfd_elf_open(const char *elf_file)
{
	struct bfd_elf_file *file = NULL;

	if (!fexist(elf_file)) {
		errno = -EEXIST;
		return NULL;
	}

	file = file_already_load(elf_file);
	if (!file)
		file = file_load(elf_file);

	return file;
}

static void __rb_free_sym(struct rb_node *node)
{
	struct bfd_sym *s = rb_entry(node, struct bfd_sym, node);
	free_sym(s);
}

int bfd_elf_close(struct bfd_elf_file *file)
{
	int i;

	if (!file)
		return -1;

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

	list_del(&file->node);

	/* Destroy all type symbols rb tree */
	for (i = 0; i < S_T_NUM; i++)
		rb_destroy(&file->rb_tree_syms[i], __rb_free_sym);

	bfd_close(file->bfd);
	free(file);
	return 0;
}

int bfd_elf_destroy(void)
{
	struct bfd_elf_file *f, *tmp;

	list_for_each_entry_safe(f, tmp, &file_list, node)
		bfd_elf_close(f);

	return 0;
}

