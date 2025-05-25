// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once
#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "elf/elf-api.h"

#include "utils/log.h"

enum vma_type {
	VMA_NONE,   /* None */
	VMA_SELF,   /* /usr/bin/ls, ... */
	VMA_LIBC,   /* libc.so.x */
	VMA_HEAP,   /* [heap] */
	VMA_LD,     /* ld-linux-xxxxx */
	VMA_STACK,  /* [stack] */
	/**
	 * kernel v6.11-rc6-414-g6d27a31ef195
	 * commit 6d27a31ef195 ("uprobes: introduce the global struct
	 * vm_special_mapping xol_mapping") introduce "[uprobes]" vma.
	 */
	VMA_UPROBES,  /* [uprobes] */
	VMA_VVAR,   /* [vvar] */
	/**
	 * kernel v6.12-rc2-33-ge93d2521b27f
	 * commit e93d2521b27f ("x86/vdso: Split virtual clock pages into
	 * dedicated mapping") introduce "[vvar_vclock]" vma.
	 */
	VMA_VVAR_VCLOCK,   /* [vvar_vclock] */
	VMA_VDSO,   /* [vdso] */
	VMA_VSYSCALL, /* [vsyscall] */
	VMA_LIB_UNKNOWN, /* Unknown Library */
	VMA_ANON,   /* No name */
	VMA_ULPATCH,/* ULPatch */
	VMA_TYPE_NUM,
};

struct task_struct;
struct bfd_elf_file;

struct vma_elf_mem {
	GElf_Ehdr ehdr;
	/**
	 * If no program headers, phdrs = NULL. Actually, in task vma mapping
	 * space, only ULP ELF don't have phdrs, other ELF like libc,self,vdso
	 * have phdrs.
	 */
	GElf_Phdr *phdrs;
	unsigned long load_addr;
};

struct vm_area_struct {
	/**
	 * vaddr = load_bias + p_vaddr
	 * addr = ELF_PAGESTART(addr)
	 * off = p_offset - ELF_PAGEOFFSET(p_vaddr)
	 * vm_pgoff = off >> PAGE_SHIFT
	 */
	unsigned long vm_start, vm_end, vm_pgoff;
	unsigned int major, minor;
	unsigned long inode;
	char name_[PATH_MAX];
	char perms[5];
#define PROT_FMT "%c%c%c"
#define PROT_ARGS(p) \
	(p & PROT_READ) ? 'r' : '-', \
	(p & PROT_WRITE) ? 'w' : '-', \
	(p & PROT_EXEC) ? 'e' : '-'
	/* parse from char perms field */
	unsigned int prot;

	enum vma_type type;

	bool is_elf;
	bool is_share_lib;
	struct {
		bool is_matched_phdr;
		/**
		 * Point to leader ELF VMA's vma::vma_elf_mem->phdrs[i] if
		 * matched.
		 */
		GElf_Phdr phdr;
	};

	/* Only elf has it */
	struct vma_elf_mem *vma_elf;

	/**
	 * If VMA is ELF file, such as the leader of VMA_SELF, VMA_LIBC and
	 * VMA_VDSO, open it as bfd.
	 */
	struct bfd_elf_file *bfd_elf_file;

	/* Only VMA_ULPATCH has it */
	struct vma_ulp *ulp;

	struct task_struct *task;

	/* struct vm_area_root.list */
	struct list_head node_list;
	/* struct vm_area_root.rb */
	struct rb_node node_rb;

	/**
	 * All same name vma in one list, and the first vma is leader.
	 * if vma == vma->leader means that this vma is leader.
	 */
	struct vm_area_struct *leader;
	struct list_head siblings;

	unsigned long voffset;
};

struct vm_area_root {
	/* struct vm_area_struct.node_list */
	struct list_head list;
	/* struct vm_area_struct.node_rb */
	struct rb_root rb;

	/* for fast seek */
	struct vm_area_struct *self_elf;
	struct vm_area_struct *libc_code;
	struct vm_area_struct *stack;

	/**
	 * Point to vma::bfd_elf_file field, no need to free or close.
	 */
	struct bfd_elf_file *exe_bfd;
	struct bfd_elf_file *libc_bfd;
};


/* Get task's first vma in rbtree */
#define first_vma(task) next_vma(task, NULL)
/* For each vma of task */
#define task_for_each_vma(vma, task) \
	for (vma = first_vma(task); vma; vma = next_vma(task, vma))

#define task_vdso_vma(task) ({	\
		struct vm_area_struct *__vma_iter, *__vma_vdso = NULL;	\
		task_for_each_vma(__vma_iter, task) {	\
			if (__vma_iter->type == VMA_VDSO) {	\
				__vma_vdso = __vma_iter;	\
			}	\
		}	\
		__vma_vdso;	\
	})

void init_vma_root(struct vm_area_root *root);

struct vm_area_struct *alloc_vma(struct task_struct *task);
void insert_vma(struct task_struct *task, struct vm_area_struct *vma,
		struct vm_area_struct *prev);
void unlink_vma(struct task_struct *task, struct vm_area_struct *vma);
void free_vma(struct vm_area_struct *vma);
int free_task_vmas(struct task_struct *task);
struct vm_area_struct *find_vma(const struct task_struct *task,
				unsigned long vaddr);
struct vm_area_struct *next_vma(struct task_struct *task,
				struct vm_area_struct *prev);
unsigned long find_vma_span_area(struct task_struct *task, size_t size,
				 unsigned long base);
unsigned int vma_perms2prot(char *perms);
int vma_prot2flags(unsigned int prot);

enum vma_type get_vma_type(pid_t pid, const char *exe, const char *name);
const char *vma_type_name(enum vma_type type);
bool elf_vma_is_interp_exception(struct vm_area_struct *vma);
int read_task_vmas(struct task_struct *task, bool update_ulp);
void print_vma(FILE *fp, bool first_line, struct vm_area_struct *vma,
	       bool detail);
void print_vma_root(FILE *fp, struct vm_area_root *root, bool detail);
