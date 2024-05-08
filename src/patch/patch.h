// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#ifndef __ELF_ULPATCH_H
#define __ELF_ULPATCH_H 1

#include <stdbool.h>
#include <stdint.h>
#include <gelf.h>

#include <utils/util.h>
#include <utils/compiler.h>

#define __ULP_DEV
#include <patch/meta.h>


#if defined(__x86_64__)
#include <arch/x86_64/instruments.h>
#include <arch/x86_64/mcount.h>
#elif defined(__aarch64__)
#include <arch/aarch64/instruments.h>
#include <arch/aarch64/mcount.h>
#include <arch/aarch64/ftrace.h>
#endif

struct vm_area_struct;

/* see linux:kernel/module-internal.h */
struct load_info {
	const char *name;
	char *ulp_name;

	GElf_Ehdr *hdr;
	unsigned long len;

	/* the VMA start address in target task/process address space */
	unsigned long target_hdr;
	struct task_struct *target_task;

	/* Create ULP_PROC_ROOT_DIR/PID/TASK_PROC_MAP_FILES/patch-XXXXXX */
	struct {
		char *path;
		struct mmap_struct *mmap;
	} patch;

	GElf_Shdr *sechdrs;
	char *secstrings, *strtab;
	unsigned long symoffs, stroffs, init_typeoffs, core_typeoffs;

	struct ulpatch_info *ulp_info;
	struct ulpatch_strtab ulp_strtab;
	/* Store Build ID if exist. malloc, need free */
	char *str_build_id;

	struct {
		unsigned int
			sym,
			str,
			vers,
			ulp_strtab,
			info,
			build_id;
	} index;
};


/* ftrace */
#if defined(__x86_64__)
# define MCOUNT_INSN_SIZE	CALL_INSN_SIZE
#elif defined(__aarch64__)
/* A64 instructions are always 32 bits. */
# define MCOUNT_INSN_SIZE	BL_INSN_SIZE
#endif


#define PATCH_VMA_TEMP_PREFIX	"ulp-"

struct jmp_table_entry {
	unsigned long jmp;
	unsigned long addr;
};

struct task_struct;

bool is_ftrace_entry(char *func);

extern void _ftrace_mcount(void);
extern void _ftrace_mcount_return(void);

int mcount_entry(unsigned long *parent_loc, unsigned long child,
			struct mcount_regs *regs);
unsigned long mcount_exit(long *retval);

void print_ulp_strtab(FILE *fp, const char *pfx, struct ulpatch_strtab *strtab);
void print_ulp_info(FILE *fp, const char *pfx, struct ulpatch_info *inf);
const char *ulp_info_strftime(struct ulpatch_info *inf);

int alloc_patch_file(const char *obj_from, const char *obj_to,
			struct load_info *info);
int vma_load_info(struct vm_area_struct *vma, struct load_info *info);
int setup_load_info(struct load_info *info);
void release_load_info(struct load_info *info);

int init_patch(struct task_struct *task, const char *obj_file);
int delete_patch(struct task_struct *task);

int apply_relocate_add(const struct load_info *info, GElf_Shdr *sechdrs,
			const char *strtab, unsigned int symindex,
			unsigned int relsec);

unsigned long arch_jmp_table_jmp(void);

#endif /* __ELF_ULPATCH_H */
