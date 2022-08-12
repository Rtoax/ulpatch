// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#pragma once

#include <string.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/prctl.h>

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
	VMA_TYPE_NUM,
};

#define VMA_TYPE_NAME(t) __VMA_TYPE_NAME[t]
static const char __unused *__VMA_TYPE_NAME[] = {
	"Unknown",
	"Self",
	"libc",
	"libelf",
	"heap",
	"ld",
	"stack",
	"vvar",
	"vDSO",
	"vsyscall",
	"UnknownLib",
	"Anon",
	NULL
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

	struct process *task;

	// struct task.vmas
	struct list_head node;
	struct rb_node node_rb;
};

static __unused enum vma_type
get_vma_type(const char *exe, const char *name)
{
	enum vma_type type = VMA_NONE;

	if (!strcmp(name, exe)) {
		type = VMA_SELF;
	} else if (!strncmp(basename((char*)name), "libc", 4)
		|| !strncmp(basename((char*)name), "libssp", 6)) {
		type = VMA_LIBC;
	} else if (!strncmp(basename((char*)name), "libelf", 6)) {
		type = VMA_LIBELF;
	} else if (!strcmp(name, "[heap]")) {
		type = VMA_HEAP;
	} else if (!strncmp(basename((char*)name), "ld-linux", 8)) {
		type = VMA_LD;
	} else if (!strcmp(name, "[stack]")) {
		type = VMA_STACK;
	} else if (!strcmp(name, "[vvar]")) {
		type = VMA_VVAR;
	} else if (!strcmp(name, "[vdso]")) {
		type = VMA_VDSO;
	} else if (!strcmp(name, "[vsyscall]")) {
		type = VMA_VSYSCALL;
	} else if (!strncmp(basename((char*)name), "lib", 3)) {
		type = VMA_LIB_DONT_KNOWN;
	} else if (strlen(name) == 0) {
		type = VMA_ANON;
	} else {
		type = VMA_NONE;
	}

	return type;
}

/* When task opening, what do you want to do?
 *
 * FTO means Flag of Task when Open.
 *
 * @FTO_LIBC in /proc/PID/maps specify a libc.so ELF file, if you want to
 *            open it when open task, set this flag.
 * @FTO_SELF task.exe or /proc/PID/exe specify a ELF file, open it or not.
 * @FTO_PROC Create '/proc' like directory under ROOT_DIR. If you need to map
 *            a file into target process address space, the flag is necessary.
 */
enum fto_flag {
	FTO_SELF = 0x1 << 0,
	FTO_LIBC = 0x1 << 1,
	FTO_PROC = 0x1 << 2,
};

#define FTO_NONE 0x0
#define FTO_ALL (FTO_SELF|FTO_LIBC|FTO_PROC)


/* under ROOT_DIR/PID/ */
#define TASK_PROC_COMM	"comm"
#define TASK_PROC_MAP_FILES	"map_files"


struct elf_file;

/* This struct use to discript a running process in system, like you can see in
 * proc file system, there are lots of HANDLE in this structure get from procfs.
 */
struct task {
	// /proc/PID/comm
	char comm[128];

	pid_t pid;

	enum fto_flag fto_flag;

	// realpath of /proc/PID/exe
	char *exe;

	/* If FTO_SELF set, load SELF ELF file when open.
	 */
	struct elf_file *exe_elf;

	// open(2) /proc/PID/mem
	int proc_mem_fd;

	struct list_head node;

	// struct vma_struct.node
	struct list_head vmas;
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
int update_task_vmas(struct task *task);

int dump_task(const struct task *t);

void print_vma(struct vma_struct *vma);
void dump_task_vmas(struct task *task);

struct task *open_task(pid_t pid, enum fto_flag flag);
int free_task(struct task *task);

int task_attach(pid_t pid);
int task_detach(pid_t pid);

int memcpy_to_task(struct task *task,
		unsigned long remote_dst, void *src, ssize_t size);
int memcpy_from_task(struct task *task,
		void *dst, unsigned long remote_src, ssize_t size);

/* syscalls based on task_syscall() */
// if mmap file, need to update_task_vmas() manual
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

/* Add wait api */
struct task_wait {
	int msqid;
	char tmpfile[64];
};

int task_wait_init(struct task_wait *task_wait, char *tmpfile);
int task_wait_destroy(struct task_wait *task_wait);
int task_wait_wait(struct task_wait *task_wait);
int task_wait_trigger(struct task_wait *task_wait);

