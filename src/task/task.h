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

#include "init.h"

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
#include <task/patch.h>
#include <task/memcpy.h>
#include <task/proc.h>
#include <task/fd.h>
#include <task/symbol.h>


/* under ULP_PROC_ROOT_DIR/${PID}/ */
#define TASK_PROC_COMM	"comm"
#define TASK_PROC_MAP_FILES	"map_files"

#define TASK_COMM_LEN	128

/**
 * This struct use to discript a running process in system, like you can see in
 * proc file system, there are lots of HANDLE in this structure get from procfs.
 */
struct task_struct {
	pid_t pid;
	char comm[TASK_COMM_LEN];
	char exe[PATH_MAX];

	int fto_flag;

	bool is_pie;

	struct task_auxv auxv;
	struct task_status status;

	/* open(2) /proc/[PID]/mem */
	int proc_mem_fd;

	struct vm_area_root vma_root;
	struct vma_ulp_root ulp_root;
	struct task_thread_root thread_root;
	struct fds_root fds_root;

	/**
	 * Store all symbols that task defined.
	 */
	struct task_syms tsyms;
};


int dump_task(FILE *fp, const struct task_struct *t, bool detail);

void dump_task_vmas(FILE *fp, struct task_struct *task, bool detail);
int dump_task_addr_to_file(const char *ofile, struct task_struct *task,
		unsigned long addr, unsigned long size);
int dump_task_vma_to_file(const char *ofile, struct task_struct *task,
		unsigned long addr);

bool elf_vma_is_interp_exception(struct vm_area_struct *vma);

struct task_struct *open_task(pid_t pid, int flag);
int close_task(struct task_struct *task);
void print_task(FILE *fp, const struct task_struct *task, bool detail);
bool task_is_pie(struct task_struct *task);

int task_attach(pid_t pid);
int task_detach(pid_t pid);
