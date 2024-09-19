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


static unsigned long offset_to_vaddr(struct vm_area_struct *vma, loff_t offset)
{
	return vma->vm_start + offset - ((loff_t)vma->vm_pgoff << PAGE_SHIFT);
}

/**
 * This function use to calculate the real symbol value, because load_addr's
 * effect.
 */
unsigned long task_vma_symbol_vaddr(const struct symbol *sym)
{
	unsigned long addr = 0;
	struct vm_area_struct *vma_leader = sym->vma;
	struct task_struct *task = vma_leader->task;
	unsigned long off = sym->sym.st_value;

	if (vma_leader != vma_leader->leader) {
		ulp_error("Symbol vma must be leader.\n");
		return 0;
	}

	if (vma_leader->is_share_lib) {
		struct vm_area_struct *vma, *tmpvma;

		list_for_each_entry_safe(vma, tmpvma, &vma_leader->siblings,
					 siblings) {

			/* Ignore vma holes, ---p */
			if (vma->prot == PROT_NONE)
				continue;

			if (off < (vma->vm_pgoff << PAGE_SHIFT))
				break;
		}

		/* FIXME: Maybe replace voffset here like VMA_SELF */
		addr = vma->vm_start + (off - vma->voffset);

	} else if (vma_leader->type == VMA_SELF) {
		/**
		 * If PIE, we should call offset_to_vaddr(), if no-PIE, use
		 * the offset directly.
		 */
		addr = task->is_pie ?
			offset_to_vaddr(sym->vma, off) :
			vma_leader->vma_elf->load_addr + off;
	} else
		addr = off;

	ulp_debug("Get symbol %s addr %lx\n", sym->name, addr);
	return addr;
}

struct symbol *task_vma_find_symbol(struct task_struct *task, const char *name,
				    int type)
{
	struct rb_node *node;
	struct symbol tmp = {
		.name = (char *)name,
		.type = type,
		.sym_type = SYM_TYPE_DEFINED,
	};

	ulp_debug("try find symbol %s\n", name);

	node = rb_search_node(&task->vma_symbols, cmp_symbol_name,
			      (unsigned long)&tmp);
	return node ? rb_entry(node, struct symbol, node) : NULL;
}

int task_vma_link_symbol(struct symbol *s, struct vm_area_struct *leader)
{
	struct rb_node *node;
	struct task_struct *task;
	struct vm_area_struct *vma;
	unsigned long vaddr;

	task = leader->task;
	vaddr = leader->vma_elf->load_addr + s->sym.st_value;

	vma = leader;

	ulp_debug("symbol: st_value %s:%lx(%lx) in vma %s:%lx\n",
	       s->name, s->sym.st_value, vaddr,
	       vma->name_, vma->vm_start);

	if (get_log_level() >= LOG_DEBUG)
		fprint_sym(get_log_fp(), &s->sym, s->name, NULL, true);

	s->vma = vma;
	s->type = GELF_ST_TYPE(s->sym.st_info);

	/**
	 * TODO: Get the symbol belongs to which phdrs.
	 */

	node = rb_insert_node(&task->vma_symbols, &s->node, cmp_symbol_name,
			      (unsigned long)s);
	if (unlikely(node))
		ulp_warning("%s: symbol %s already exist\n", task->comm, s->name);
	else
		ulp_debug("%s: add symbol %s addr %lx success.\n", task->comm,
			s->name, s->sym.st_value);
	return node ? -EINVAL : 0;
}

int task_vma_alloc_link_symbol(struct vm_area_struct *leader, const char *name,
			       GElf_Sym *sym)
{
	int err = 0;
	struct symbol *new;

	/* skip undefined symbols */
	if (is_undef_symbol(sym)) {
		ulp_debug("%s undef symbol: %s %lx\n", basename(leader->name_),
			name, sym->st_value);
		/* Skip undefined symbol */
		if (get_log_level() >= LOG_DEBUG)
			fprint_sym(get_log_fp(), sym, name, NULL, true);
		return 0;
	}

	/* allocate a symbol, and add it to task struct */
	new = alloc_symbol(name, sym);
	if (!new) {
		ulp_error("Alloc symbol failed, %s\n", name);
		return -ENOMEM;
	}

	ulp_debug("SELF %s %lx\n", new->name, new->sym.st_value);
	err = task_vma_link_symbol(new, leader);
	if (err)
		free_symbol(new);

	return err;
}

/**
 * load_self_vma_symbols - load self symbols from ELF file
 *
 * @vma - self vma
 */
static int load_self_vma_symbols(struct vm_area_struct *leader)
{
	int err = 0;
	struct task_struct *task = leader->task;
	struct symbol *sym, *tmp;
	struct rb_root *root = &task->exe_elf->symbols;

	rbtree_postorder_for_each_entry_safe(sym, tmp, root, node)
		err |= task_vma_alloc_link_symbol(leader, sym->name, &sym->sym);

	return err;
}

int vma_load_all_symbols(struct vm_area_struct *vma)
{
	int err = 0;
	size_t i;
	GElf_Dyn *dynamics = NULL;
	GElf_Phdr *dynamic_phdr = NULL;
	GElf_Sym *syms = NULL;
	char *buffer = NULL;
	struct task_struct *task;

	unsigned long symtab_addr, strtab_addr;
	unsigned long symtab_sz, strtab_sz;


	if (!vma->is_elf || !vma->vma_elf)
		return 0;

	task = vma->task;

	symtab_addr = strtab_addr = 0;
	symtab_sz = strtab_sz = 0;


	/* load all self symbols */
	if (vma->type == VMA_SELF)
		return load_self_vma_symbols(vma);

	/**
	 * Find PT_DYNAMIC program header
	 */
	for (i = 0; i < vma->vma_elf->ehdr.e_phnum; i++) {
		if (vma->vma_elf->phdrs[i].p_type == PT_DYNAMIC) {
			dynamic_phdr = &vma->vma_elf->phdrs[i];
			break;
		}
	}

	if (!dynamic_phdr) {
		ulp_error("No PT_DYNAMIC in %s\n", vma->name_);
		return -ENOENT;
	}

	dynamics = malloc(dynamic_phdr->p_memsz);
	if (!dynamics) {
		ulp_error("Malloc dynamics failed %s\n", vma->name_);
		return -ENOMEM;
	}

	err = memcpy_from_task(task, dynamics,
			       vma->vma_elf->load_addr + dynamic_phdr->p_vaddr,
			       dynamic_phdr->p_memsz);
	if (err == -1 || err < dynamic_phdr->p_memsz) {
		ulp_error("Task read mem failed, %lx.\n",
			vma->vm_start + dynamic_phdr->p_vaddr);
		goto out_free;
	}

	/* For each Dynamic */
	for (i = 0; i < dynamic_phdr->p_memsz / sizeof(GElf_Dyn); i++) {
		GElf_Dyn *curdyn = dynamics + i;

		switch (curdyn->d_tag) {
		case DT_SYMTAB:
			symtab_addr = curdyn->d_un.d_ptr;
			break;
		case DT_STRTAB:
			strtab_addr = curdyn->d_un.d_ptr;
			break;
		case DT_STRSZ:
			strtab_sz = curdyn->d_un.d_val;
			break;
		case DT_SYMENT:
			if (curdyn->d_un.d_val != sizeof(GElf_Sym)) {
				ulp_error("Dynsym entry size is %ld expected %ld\n",
					curdyn->d_un.d_val, sizeof(GElf_Sym));
				goto out_free;
			}
			break;
		default:
			break;
		}
	}

	symtab_sz = (strtab_addr - symtab_addr);

	if (strtab_sz == 0 || symtab_sz == 0) {
		memshowinlog(LOG_INFO, dynamics, dynamic_phdr->p_memsz);
		ulp_warning("No strtab, p_memsz %ld, p_vaddr %lx. "
			 "strtab(%lx) symtab(%lx) %s %lx\n",
			 dynamic_phdr->p_memsz, dynamic_phdr->p_vaddr,
			 strtab_addr, symtab_addr, vma->name_, vma->vm_start);
	}

	buffer = malloc(symtab_sz + strtab_sz);
	if (!buffer) {
		ulp_error("Malloc %ld bytes failed\n", symtab_sz + strtab_sz);
		goto out_free;
	}
	memset(buffer, 0x0, symtab_sz + strtab_sz);

	ulp_debug("%s: symtab_addr %lx, load_addr: %lx, vma start %lx\n",
		vma->name_,
		symtab_addr,
		vma->vma_elf->load_addr,
		vma->vm_start);

	/**
	 * [vdso] need add load_addr or vma start address.
	 *
	 * $ readelf -S vdso.so
	 * There are 16 section headers, starting at offset 0xe98:
	 * Section Headers:
	 *  [Nr] Name              Type             Address           Offset
	 *       Size              EntSize          Flags  Link  Info  Align
	 *  [ 3] .dynsym           DYNSYM           00000000000001c8  000001c8
	 *       0000000000000138  0000000000000018   A       4     1     8
	 */
	if (vma->type == VMA_VDSO)
		symtab_addr += vma->vma_elf->load_addr;

	err = memcpy_from_task(task, buffer, symtab_addr, strtab_sz + symtab_sz);
	if (err == -1 || err < strtab_sz + symtab_sz) {
		ulp_error("load symtab failed.\n");
		goto out_free_buffer;
	}

	ulp_debug("%s\n", vma->name_);
	memshowinlog(LOG_INFO, buffer, strtab_sz + symtab_sz);

	/* For each symbol */
	syms = (GElf_Sym *)buffer;

	for (i = 0; i < symtab_sz / sizeof(GElf_Sym); i++) {
		struct symbol *s;
		GElf_Sym *sym = syms + i;
		const char *symname = buffer + symtab_sz + syms[i].st_name;

		if (is_undef_symbol(sym) || strlen(symname) == 0)
			continue;

		ulp_debug("%s: %s\n", vma->name_, symname);

		/* allocate a symbol, and add it to task struct */
		s = alloc_symbol(symname, sym);
		if (!s) {
			ulp_error("Alloc symbol failed, %s\n", symname);
			continue;
		}

		err = task_vma_link_symbol(s, vma);
		if (err)
			free_symbol(s);
	}

out_free_buffer:
	free(buffer);
out_free:
	free(dynamics);
	return 0;
}

/**
 * New API of task symbols
 */

static inline int __cmp_task_sym(struct rb_node *n1, unsigned long key)
{
	struct task_sym *s1 = rb_entry(n1, struct task_sym, node);
	struct task_sym *s2 = (struct task_sym *)key;
	return strcmp(s1->name, s2->name);
}

struct task_sym *find_task_sym(struct task_struct *task, const char *name)
{
	struct rb_root *root;
	struct rb_node *node;
	struct task_sym tmp = {
		.name = (char *)name,
	};
	root = &task->tsyms;
	node = rb_search_node(root, __cmp_task_sym, (unsigned long)&tmp);
	return node ? rb_entry(node, struct task_sym, node) : NULL;
}

int link_task_sym(struct task_struct *task, struct task_sym *s)
{
	struct rb_root *root;
	struct rb_node *node;
	root = &task->tsyms;
	node = rb_insert_node(root, &s->node, __cmp_task_sym, (unsigned long)s);
	return node ? -1 : 0;
}

struct task_sym *next_task_sym(struct task_struct *task, struct task_sym *prev)
{
	struct rb_root *root;
	struct rb_node *next;
	root = &task->tsyms;
	next = prev ? rb_next(&prev->node) : rb_first(root);
	return next ? rb_entry(next, struct task_sym, node) : NULL;
}
