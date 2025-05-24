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

#include <patch/patch.h>

#include <utils/util.h>
#include <utils/bitops.h>
#include <utils/rbtree.h>
#include <utils/list.h>
#include <utils/compiler.h>

#include <task/auxv.h>
#include <task/current.h>
#include <task/flags.h>
#include <task/syscall.h>
#include <task/thread.h>
#include <task/vma.h>
#include <task/proc.h>
#include <task/fd.h>
#include <task/symbol.h>


struct vma_ulp {
	struct ulpatch_strtab strtab;
	struct ulpatch_author author;
	struct ulpatch_license license;
	struct ulpatch_info info;

	/* This is ELF */
	void *elf_mem;

#define MIN_ULP_START_VMA_ADDR	0x400000U
#define MAX_ULP_START_VMA_ADDR	0xFFFFFFFFUL
	/* Belongs to */
	struct vm_area_struct *vma;

	char *str_build_id;

	/* struct task_struct.ulp_list */
	struct list_head node;
};

/* under ULP_PROC_ROOT_DIR/${PID}/ */
#define TASK_PROC_COMM	"comm"
#define TASK_PROC_MAP_FILES	"map_files"

#define TASK_COMM_LEN	128

/**
 * This struct use to discript a running process in system, like you can see in
 * proc file system, there are lots of HANDLE in this structure get from procfs.
 */
struct task_struct {
	/* /proc/[PID]/comm */
	char comm[TASK_COMM_LEN];

	pid_t pid;

	int fto_flag;

	/* realpath of /proc/PID/exe */
	char exe[PATH_MAX];

	bool is_pie;

	struct task_auxv auxv;
	struct task_status status;

	/* open(2) /proc/[PID]/mem */
	int proc_mem_fd;

	/* struct vm_area_struct.node_list */
	struct list_head vma_list;
	/* struct vm_area_struct.node_rb */
	struct rb_root vmas_rb;

	/* VMA_SELF ELF vma */
	struct vm_area_struct *vma_self_elf;
	struct vm_area_struct *libc_vma;

	struct vm_area_struct *stack;

	/**
	 * Store all symbols that task defined.
	 */
	struct task_syms tsyms;

	/**
	 * Point to vma::bfd_elf_file field, no need to free or close.
	 */
	struct bfd_elf_file *exe_bfd;
	struct bfd_elf_file *libc_bfd;

	/* struct vma_ulp.node */
	struct list_head ulp_list;
	unsigned int max_ulp_id;

	/* struct thread_struct.node */
	struct list_head threads_list;

	/* struct fd.node */
	struct list_head fds_list;
};


int update_task_vmas_ulp(struct task_struct *task);
int free_task_vmas(struct task_struct *task);

int dump_task(FILE *fp, const struct task_struct *t, bool detail);

void dump_task_vmas(FILE *fp, struct task_struct *task, bool detail);
int dump_task_addr_to_file(const char *ofile, struct task_struct *task,
		unsigned long addr, unsigned long size);
int dump_task_vma_to_file(const char *ofile, struct task_struct *task,
		unsigned long addr);
void dump_task_threads(FILE *fp, struct task_struct *task, bool detail);
void dump_task_fds(FILE *fp, struct task_struct *task, bool detail);

bool elf_vma_is_interp_exception(struct vm_area_struct *vma);

int alloc_ulp(struct vm_area_struct *vma);
void free_ulp(struct vm_area_struct *vma);

int print_task_status(FILE *fp, const struct task_struct *task);

struct task_struct *open_task(pid_t pid, int flag);
int close_task(struct task_struct *task);
void print_task(FILE *fp, const struct task_struct *task, bool detail);
bool task_is_pie(struct task_struct *task);

int task_attach(pid_t pid);
int task_detach(pid_t pid);

int memcpy_to_task(struct task_struct *task, unsigned long remote_dst,
		   void *src, ssize_t size);
int memcpy_from_task(struct task_struct *task, void *dst,
		     unsigned long remote_src, ssize_t size);
char *strcpy_from_task(struct task_struct *task, char *dst,
		       unsigned long task_src);
char *strcpy_to_task(struct task_struct *task, unsigned long task_dst,
		     char *src);
