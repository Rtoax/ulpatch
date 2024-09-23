// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <limits.h>
#include <stdlib.h>
#include <elf.h>
#include <dirent.h>

#include <elf/elf-api.h>

#include <utils/log.h>
#include <utils/task.h>


static inline int __cmp_task_sym(struct rb_node *n1, unsigned long key)
{
	struct task_sym *s1 = rb_entry(n1, struct task_sym, sort_by_name);
	struct task_sym *s2 = (struct task_sym *)key;
	return strcmp(s1->name, s2->name);
}

static inline int __cmp_task_addr(struct rb_node *n1, unsigned long key)
{
	struct task_sym *s1 = rb_entry(n1, struct task_sym, sort_by_addr);
	struct task_sym *s2 = (struct task_sym *)key;
	return s1->addr - s2->addr;
}

static void __rb_free_task_sym(struct rb_node *node)
{
	struct task_sym *s = rb_entry(node, struct task_sym, sort_by_name);
	free_task_sym(s);
}

struct task_sym *alloc_task_sym(const char *name, unsigned long addr,
				struct vm_area_struct *vma)
{
	struct task_sym *s = malloc(sizeof(struct task_sym));

	memset(s, 0, sizeof(*s));

	s->name = strdup(name);
	s->addr = addr;
	s->vma = vma;
	s->list_addr.is_head = false;
	list_init(&s->list_addr.head);

	return s;
}

void free_task_sym(struct task_sym *s)
{
	if (s->list_addr.is_head) {
		struct task_sym *node, *tmp;
		list_for_each_entry_safe(node, tmp,
		    &s->list_addr.head, list_addr.node)
			list_del(&node->list_addr.node);
	} else
		list_del(&s->list_addr.node);

	free(s->name);
	free(s);
}

struct task_sym *find_task_sym(struct task_struct *task, const char *name)
{
	struct rb_root *root;
	struct rb_node *node;
	struct task_sym tmp = {
		.name = (char *)name,
	};
	root = &task->tsyms.rb_syms;
	node = rb_search_node(root, __cmp_task_sym, (unsigned long)&tmp);
	return node ? rb_entry(node, struct task_sym, sort_by_name) : NULL;
}

struct task_sym *find_task_addr(struct task_struct *task, unsigned long addr)
{
	struct rb_root *root;
	struct rb_node *node;
	struct task_sym tmp = {
		.addr = addr,
	};
	root = &task->tsyms.rb_addrs;
	node = rb_search_node(root, __cmp_task_addr, (unsigned long)&tmp);
	return node ? rb_entry(node, struct task_sym, sort_by_addr) : NULL;
}

int link_task_sym(struct task_struct *task, struct task_sym *s)
{
	struct rb_root *root;
	struct rb_node *node;

	root = &task->tsyms.rb_syms;

	node = rb_insert_node(root, &s->sort_by_name, __cmp_task_sym,
		       (unsigned long)s);

	ulp_debug("TSYM new %s, %lx\n", s->name, s->addr);

	/* If insert new symbol, then, insert it to the tree sorted by
	 * address */
	if (!node) {
		struct task_sym *head;
		head = find_task_addr(task, s->addr);
		if (head) {
			list_add(&s->list_addr.node, &head->list_addr.head);
			ulp_debug("TADDR dup %lx %s\n", s->addr, s->name);
		} else {
			root = &task->tsyms.rb_addrs;
			rb_insert_node(root, &s->sort_by_addr,
					__cmp_task_addr, (unsigned long)s);
			list_init(&s->list_addr.head);
			s->list_addr.is_head = true;
			ulp_debug("TADDR new %lx %s\n", s->addr, s->name);
		}
	}

	return node ? -1 : 0;
}

struct task_sym *next_task_sym(struct task_struct *task, struct task_sym *prev)
{
	struct rb_root *root;
	struct rb_node *next;
	root = &task->tsyms.rb_syms;
	next = prev ? rb_next(&prev->sort_by_name) : rb_first(root);
	return next ? rb_entry(next, struct task_sym, sort_by_name) : NULL;
}

struct task_sym *next_task_addr(struct task_struct *task, struct task_sym *prev)
{
	struct rb_root *root;
	struct rb_node *next;
	root = &task->tsyms.rb_addrs;
	next = prev ? rb_next(&prev->sort_by_addr) : rb_first(root);
	return next ? rb_entry(next, struct task_sym, sort_by_addr) : NULL;
}

int task_load_vma_elf_syms(struct vm_area_struct *vma)
{
	struct task_struct *task;
	struct bfd_elf_file *bfile;
	struct bfd_sym *bsym;
	struct task_sym *tsym;

	if (!vma->is_elf || !vma->bfd_elf_file) {
		ulp_debug("vma %s is not elf or not opened.\n", vma->name_);
		return -EINVAL;
	}

	/**
	 * FIXME: ULP ELF VMA don't has vma::vma_elf value, maybe we should
	 * resolve symbol same as oridinary ELF VMA.
	 */
	if (vma->type == VMA_ULPATCH)
		return -EINVAL;

	task = vma->task;
	bfile = vma->bfd_elf_file;

	for (bsym = bfd_next_text_sym(bfile, NULL); bsym;
		bsym = bfd_next_text_sym(bfile, bsym)) {
		const char *name = bfd_sym_name(bsym);
		unsigned long addr = bfd_sym_addr(bsym);
		unsigned long off = vma->vma_elf->load_addr;

		tsym = alloc_task_sym(name, addr + off, vma);
		link_task_sym(task, tsym);
	}

	for (bsym = bfd_next_data_sym(bfile, NULL); bsym;
		bsym = bfd_next_data_sym(bfile, bsym)) {
		const char *name = bfd_sym_name(bsym);
		unsigned long addr = bfd_sym_addr(bsym);
		unsigned long off = vma->vma_elf->load_addr;

		tsym = alloc_task_sym(name, addr + off, vma);
		link_task_sym(task, tsym);
	}

	for (bsym = bfd_next_plt_sym(bfile, NULL); bsym;
		bsym = bfd_next_plt_sym(bfile, bsym)) {
		const char *name = bfd_sym_name(bsym);
		unsigned long addr = bfd_sym_addr(bsym);
		unsigned long off = vma->vma_elf->load_addr;

		tsym = alloc_task_sym(name, addr + off, vma);
		link_task_sym(task, tsym);
	}

	return 0;
}

void free_task_syms(struct task_struct *task)
{
	rb_destroy(&task->tsyms.rb_syms, __rb_free_task_sym);
}
