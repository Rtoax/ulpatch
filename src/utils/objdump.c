// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdio.h>
#include <malloc.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <elf/elf_api.h>

#include "log.h"
#include "util.h"
#include "list.h"


enum sym_type {
	S_T_PLT, // @plt
	S_T_MUM,
};

struct objdump_elf_file {
	char name[MAX_PATH];
	/* head is file_list */
	struct list_head node;

	struct rb_root syms[S_T_MUM];
};

struct objdump_symbol {
	char *sym;
	unsigned long addr;
	enum sym_type type;

	/* root is objdump_elf_file.syms[type] */
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

// the @key is (unsigned long)objdump_elf_file
static __unused inline int cmp_sym(struct rb_node *n1, unsigned long key)
{
	struct objdump_symbol *s1 = rb_entry(n1, struct objdump_symbol, node);
	struct objdump_symbol *s2 = (struct objdump_symbol*)key;

	return strcmp(s1->sym, s2->sym);
}

static __unused struct objdump_symbol *
alloc_sym(const char *name, unsigned long addr, enum sym_type type)
{
	struct objdump_symbol *s = malloc(sizeof(struct objdump_symbol));

	memset(s, 0, sizeof(*s));

	s->sym = strdup(name);
	s->addr = addr;
	s->type = type;

	return s;
}

static __unused void free_sym(struct objdump_symbol *s)
{
	free(s->sym);
	free(s);
}

static __unused struct objdump_symbol *
find_sym(struct rb_root *root, const char *sym)
{
	struct objdump_symbol tmp = {
		.sym = (char *)sym,
	};
	struct rb_node *node = rb_search_node(root,
						cmp_sym, (unsigned long)&tmp);

	return node?rb_entry(node, struct objdump_symbol, node):NULL;
}

/* Insert OK, return 0, else return -1 */
static __unused int link_sym(struct rb_root *root, struct objdump_symbol *s)
{
	struct rb_node *node = rb_insert_node(root, &s->node,
						cmp_sym, (unsigned long)s);
	return node?-1:0;
}


static int objdump_elf_load_plt(struct objdump_elf_file *file)
{
	FILE *fp;
	char cmd[BUFFER_SIZE], line[BUFFER_SIZE];

	/* $ objdump -d test
	 *
	 * [...]
	 *
	 * Disassembly of section .plt:
	 *
	 * 0000000000403020 <.plt>:
	 *  403020:	ff 35 e2 9f 01 00    	pushq  0x19fe2(%rip)        # 41d008 <_GLOBAL_OFFSET_TABLE_+0x8>
	 *  403026:	ff 25 e4 9f 01 00    	jmpq   *0x19fe4(%rip)        # 41d010 <_GLOBAL_OFFSET_TABLE_+0x10>
	 *  40302c:	0f 1f 40 00          	nopl   0x0(%rax)
	 *
	 * 0000000000403030 <gelf_getehdr@plt>:
	 *  403030:	ff 25 e2 9f 01 00    	jmpq   *0x19fe2(%rip)        # 41d018 <gelf_getehdr@ELFUTILS_1.0>
	 *  403036:	68 00 00 00 00       	pushq  $0x0
	 *  40303b:	e9 e0 ff ff ff       	jmpq   403020 <.plt>
	 *
	 * To get '0000000000403030 <gelf_getehdr@plt>:':
	 *
	 * $ objdump -d test | grep @plt | grep ^0
	 */
	snprintf(cmd, BUFFER_SIZE,
		"objdump -d %s | grep @plt | grep ^0", file->name);

	fp = popen(cmd, "r");

	while (1) {
		unsigned long addr;
		char sym[256];
		int ret;

		if (!fgets(line, sizeof(line), fp))
			break;

		ret = sscanf(line, "%lx %s", &addr, sym);
		if (ret <= 0) {
			lerror("sscanf failed.\n");
			continue;
		}

		/* For example:
		 * 0000000000403030 <gelf_getehdr@plt>:
		 *
		 * $addr: 0000000000403030
		 * $sym:  <gelf_getehdr@plt>:
		 */
		char *s = sym + 1;
		int slen = strlen(s);

		if (!strstr(s, "@plt>:")) {
			lerror("Wrong format: %s\n", sym);
			continue;
		}

		s[slen - strlen("@plt>:")] = '\0';

		linfo("%s: %#08lx %s\n", basename(file->name), addr, s);
	}

	pclose(fp);

	return 0;
}

static struct objdump_elf_file* file_load(const char *filename)
{
	struct objdump_elf_file *file;

	file = malloc(sizeof(struct objdump_elf_file));

	strncpy(file->name, filename, MAX_PATH - 1);

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
	if (!file) {
		file = file_load(elf_file);
	}

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


static void rb_free_sym(struct rb_node *node) {
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
		for (i = 0; i < S_T_MUM; i++)
			rb_destroy(&f->syms[i], rb_free_sym);

		free(f);
	}

	return 0;
}

