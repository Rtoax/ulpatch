// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once

#include <string.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <gelf.h>
#include <bfd.h>

#include "utils/util.h"
#include "utils/bitops.h"
#include "utils/rbtree.h"
#include "utils/list.h"

struct task_struct;

struct task_sym {
/* Public */
	char *name;
	unsigned long addr;
	struct vm_area_struct *vma;

/* Private */

#define TS_REFCOUNT_NOT_USED	0
	size_t refcount;

	/* root is struct task_syms.rb_syms */
	struct rb_node sort_by_name;
	/* root is struct task_syms.rb_addrs */
	struct rb_node sort_by_addr;

	struct {
		bool is_head;
		union {
			struct list_head head;
			struct list_head node;
		};
	}
	/**
	 * Maybe more than one symbols have same address, if that, the first
	 * symbol inserted to task_syms::addrs with node task_sym::sort_by_addr,
	 * and task_sym::list_addr::head initialized as list head. The
	 * following inserted symbol's task_sym::sort_by_addr was ignored, and
	 * insert to first task_sym::list_addr::head with node
	 * task_sym::list_addr::node.
	 *
	 *                task_syms::addrs
	 *                        ()
	 *                        /\
	 *                       /  \
	 *                      /   ...
	 *                     ()
	 *  task_sym::sort_by_addr             task_sym
	 *            [list_addr::head]<-->[list_addr::node]<-->[...]
	 */
	list_addr,
	/**
	 * Why one symbol could has more than one addresses?
	 * First of all, BFD will parse symbol from the execution and dynamic
	 * library ELF file, @plt symbol will be parsed from execution ELF, and
	 * real symbol address will be parsed from dynamic library. For
	 * example: pthread_create has two address, one is @plt, another one is
	 * in libc.
	 *
	 * FIXME: No matter if we use @plt or real symbol value, i think it's
	 * same.
	 */
	list_name;
};

struct task_syms {
	/**
	 * rb_syms:
	 * - node is struct task_sym.sort_by_name
	 * rb_addrs:
	 * - node is struct task_sym.sort_by_addr
	 */
	struct rb_root rb_syms, rb_addrs;
};

static inline void task_syms_init(struct task_syms *tsyms) {
	rb_init(&tsyms->rb_syms);
	rb_init(&tsyms->rb_addrs);
}

/* Task symbol APIs */
struct task_sym *alloc_task_sym(const char *name, unsigned long addr,
				struct vm_area_struct *vma);
void free_task_sym(struct task_sym *s);

struct task_sym *find_task_sym(struct task_struct *task, const char *name,
			       const struct task_sym ***extras,
			       size_t *nr_extras);
struct task_sym *find_task_addr(struct task_struct *task, unsigned long addr);

int link_task_sym(struct task_struct *task, struct task_sym *s);

struct task_sym *next_task_sym(struct task_struct *task, struct task_sym *prev);
struct task_sym *next_task_addr(struct task_struct *task,
				struct task_sym *prev);

int task_load_vma_elf_syms(struct vm_area_struct *vma);
void free_task_syms(struct task_struct *task);
