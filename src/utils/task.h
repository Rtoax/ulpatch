#pragma once

#include <sys/types.h>

#include "list.h"
#include "compiler.h"

enum vma_type {
	VMA_NONE,   /* None */
	VMA_SELF,   /* /usr/bin/ls, ... */
	VMA_LIBC,   /* /usr/lib64/libc.so.x */
	VMA_HEAP,   /* [heap] */
	VMA_LD,     /* /usr/lib64/ld-linux-xxxxx */
	VMA_STACK,  /* [stack] */
	VMA_VVAR,   /* [vvar] */
	VMA_VDSO,   /* [vdso] */
	VMA_VSYSCALL, /* [vsyscall] */
	VMA_LIB_DONT_KNOWN, /* Unknown Library */
	VMA_ANON,   /* No name */
	VMA_FTRACE_TRAMPOLINE,  /* ftrace trampoline */
	VMA_PATCH_OBJ, /* User space patch object file */
	VMA_TYPE_NUM,
};

#define VMA_TYPE_NAME(t) __VMA_TYPE_NAME[t]
static const char __unused *__VMA_TYPE_NAME[] = {
	"Unknown",
	"Self",
	"libc",
	"heap",
	"ld",
	"stack",
	"vvar",
	"vDSO",
	"vsyscall",
	"UnknownLib",
	"Anon",
	"Trampoline",
	"PatchObj",
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
};

struct task {
	pid_t pid;

	// open(2) /proc/PID/mem
	int proc_mem_fd;
	// open(2) /proc/PID/maps
	int proc_maps_fd;

	struct list_head node;

	// struct vma_struct.node
	struct list_head vmas;
};


int open_pid_maps(pid_t pid);
int open_pid_mem(pid_t pid);

struct task *open_task(pid_t pid);
int free_task(struct task *task);
