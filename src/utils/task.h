// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#pragma once

#include <string.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <gelf.h>

#ifdef HAVE_BINUTILS_BFD_H
#include <bfd.h>
#else
#error "Must install binutils-devel"
#endif

#include <utils/util.h>
#include <utils/rbtree.h>
#include <utils/list.h>
#include <utils/compiler.h>

enum vma_type {
	VMA_NONE,   /* None */
	VMA_SELF,   /* /usr/bin/ls, ... */
	VMA_LIBC,   /* /usr/lib64/libc.so.x */
	VMA_LIBELF, /* /usr/lib64/libelf... */
	VMA_HEAP,   /* [heap] */
	VMA_LD,     /* /usr/lib64/ld-linux-xxxxx */
	VMA_STACK,  /* [stack] */
	VMA_VVAR,   /* [vvar] */
	VMA_VDSO,   /* [vdso] */
	VMA_VSYSCALL, /* [vsyscall] */
	VMA_LIB_DONT_KNOWN, /* Unknown Library */
	VMA_ANON,   /* No name */
	VMA_ULPATCH,/* ULPatch */
	VMA_TYPE_NUM,
};

#define VMA_TYPE_NAME(t) __VMA_TYPE_NAME[t]
static const char __unused *__VMA_TYPE_NAME[] = {
	"unknown",
	"self",
	"libc",
	"libelf",
	"heap",
	"ld",
	"stack",
	"vvar",
	"vdso",
	"vsyscall",
	"lib?",
	"anon",
	"ulpatch",
	NULL
};

struct vma_elf {
	GElf_Ehdr ehdr;
	GElf_Phdr *phdrs;
	unsigned long load_offset;
};

struct vma_struct {
	unsigned long start, end, offset;
	unsigned int maj, min, inode;
	char perms[5], name_[256];
#define PROT_FMT "%c%c%c"
#define PROT_ARGS(p) \
	(p & PROT_READ) ? 'r' : '-', \
	(p & PROT_WRITE) ? 'w' : '-', \
	(p & PROT_EXEC) ? 'e' : '-'
	unsigned int prot; /* parse from char perms[5] */

	enum vma_type type;

	bool is_elf;
	bool is_share_lib;
	bool is_matched_phdr;

	/* Only elf has it */
	struct vma_elf *elf;

	struct task *task;

	/* struct task.vma_list */
	struct list_head node_list;
	/* struct task.vmas_rb */
	struct rb_node node_rb;

	/* All same name vma in one list, and the first vma is leader.
	 * if vma == vma->leader means that this vma is leader.
	 */
	struct vma_struct *leader;
	struct list_head siblings;

	unsigned long voffset;
};

/* When task opening, what do you want to do?
 *
 * FTO means Flag of Task when Open.
 *
 * @FTO_LIBC in /proc/PID/maps specify a libc.so ELF file, if you want to
 *            open it when open task, set this flag.
 * @FTO_SELF task.exe or /proc/PID/exe specify a ELF file, open it or not.
 * @FTO_PROC Create '/proc' like directory under ROOT_DIR. If you need to map
 *            a file into target process address space, the flag is necessary.
 * @FTO_PATCH parse patch VMA when open a task.
 * @FTO_VMA_ELF different with @FTO_LIBC, it's open target process address
 *               space's ELF VMA in memory.
 * @FTO_VMA_ELF_SYMBOLS load each ELF VMA's PT_DYNAMIC, at same time, for load
 *                all symbols, need to load SELF
 * @FTO_SELF_PLT load elf file's @plt symbol address value by objdump.
 *                 ftrace/patch will need those @plt address value.
 */
#define FTO_NONE	0x0
#define FTO_SELF	BIT(0)
#define FTO_LIBC	BIT(1)
#define FTO_PROC	BIT(2)
#define FTO_PATCH	BIT(3)
#define FTO_VMA_ELF	BIT(4)
#define FTO_VMA_ELF_SYMBOLS	(BIT(5) | FTO_VMA_ELF | FTO_SELF)
#define FTO_SELF_PLT	BIT(6)

#define FTO_ALL 0xffffffff

#define FTO_ULFTRACE	(FTO_PROC | FTO_PATCH | FTO_VMA_ELF_SYMBOLS \
					| FTO_SELF_PLT)
#define FTO_ULPATCH	FTO_ULFTRACE

/* under ROOT_DIR/PID/ */
#define TASK_PROC_COMM	"comm"
#define TASK_PROC_MAP_FILES	"map_files"


struct elf_file;

#define TASK_COMM_LEN	128

/* This struct use to discript a running process in system, like you can see in
 * proc file system, there are lots of HANDLE in this structure get from procfs.
 */
struct task {
	/* /proc/[PID]/comm */
	char comm[TASK_COMM_LEN];

	pid_t pid;

	int fto_flag;

	/* realpath of /proc/PID/exe */
	char *exe;

	/* If FTO_SELF set, load SELF ELF file when open. */
	struct elf_file *exe_elf;

	/* open(2) /proc/[PID]/mem */
	int proc_mem_fd;

	/* struct vma_struct.node_list */
	struct list_head vma_list;
	/* struct vma_struct.node_rb */
	struct rb_root vmas_rb;

	struct vma_struct *libc_vma;

	/* if we found libc library, open it when open task with PID, and load all
	 * symbol. when patch/ftrace command launched, it is useful to handle rela
	 * symbol.
	 *
	 * Check FTO_LIBC
	 */
	struct elf_file *libc_elf;

	struct vma_struct *stack;

	/* save all symbol for fast search
	 * struct symbol.node
	 */
	struct rb_root vma_symbols;

	struct objdump_elf_file *objdump;
};


int open_pid_maps(pid_t pid);
int open_pid_mem(pid_t pid);

bool proc_pid_exist(pid_t pid);
char *get_proc_pid_exe(pid_t pid, char *buf, size_t bufsz);

struct vma_struct *next_vma(struct task *task, struct vma_struct *prev);

/* Get task's first vma in rbtree */
#define first_vma(task) next_vma(task, NULL)
/* For each vma of task */
#define task_for_each_vma(vma, task) \
		for (vma = first_vma(task); vma; vma = next_vma(task, vma))

struct vma_struct *find_vma(struct task *task, unsigned long vaddr);
/* Find a span area between two vma */
unsigned long find_vma_span_area(struct task *task, size_t size);
int read_task_vmas(struct task *task);
int update_task_vmas(struct task *task);
int free_task_vmas(struct task *task);

enum vma_type get_vma_type(pid_t pid, const char *exe, const char *name);

int dump_task(const struct task *t);

void print_vma(FILE *fp, struct vma_struct *vma, bool detail);
void dump_task_vmas(struct task *task, bool detail);
int dump_task_addr_to_file(const char *ofile, struct task *task,
		unsigned long addr, unsigned long size);
int dump_task_vma_to_file(const char *ofile, struct task *task,
		unsigned long addr);

struct task *open_task(pid_t pid, int flag);
int free_task(struct task *task);

int task_attach(pid_t pid);
int task_detach(pid_t pid);

int memcpy_to_task(struct task *task,
		unsigned long remote_dst, void *src, ssize_t size);
int memcpy_from_task(struct task *task,
		void *dst, unsigned long remote_src, ssize_t size);

/* syscalls based on task_syscall() */
/* if mmap file, need to update_task_vmas() manual */
unsigned long task_mmap(struct task *task,
	unsigned long addr, size_t length, int prot, int flags,
	int fd, off_t offset);
int task_munmap(struct task *task, unsigned long addr, size_t size);
int task_msync(struct task *task, unsigned long addr, size_t length, int flags);
int task_msync_sync(struct task *task, unsigned long addr, size_t length);
int task_msync_async(struct task *task, unsigned long addr, size_t length);
unsigned long task_malloc(struct task *task, size_t length);
int task_free(struct task *task, unsigned long addr, size_t length);
int task_open(struct task *task, char *pathname, int flags, mode_t mode);
int task_close(struct task *task, int remote_fd);
int task_ftruncate(struct task *task, int remote_fd, off_t length);
int task_fstat(struct task *task, int remote_fd, struct stat *statbuf);
int task_prctl(struct task *task, int option, unsigned long arg2,
	unsigned long arg3, unsigned long arg4, unsigned long arg5);

/* Execute a syscall(2) in target task */
int task_syscall(struct task *task, int nr,
		unsigned long arg1, unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5, unsigned long arg6,
		unsigned long *res);

struct symbol *task_vma_find_symbol(struct task *task, const char *name);
unsigned long task_vma_symbol_value(struct symbol *sym);

