#pragma once

#include <string.h>
#include <sys/types.h>

#include "rbtree.h"
#include "list.h"
#include "compiler.h"

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
get_vma_type(const char *comm, const char *name)
{
	enum vma_type type = VMA_NONE;

	if (!strcmp(name, comm)) {
		type = VMA_SELF;
	} else if (!strncmp(basename(name), "libc", 4)
		|| !strncmp(basename(name), "libssp", 6)) {
		type = VMA_LIBC;
	} else if (!strncmp(basename(name), "libelf", 6)) {
		type = VMA_LIBELF;
	} else if (!strcmp(name, "[heap]")) {
		type = VMA_HEAP;
	} else if (!strncmp(basename(name), "ld-linux", 8)) {
		type = VMA_LD;
	} else if (!strcmp(name, "[stack]")) {
		type = VMA_STACK;
	} else if (!strcmp(name, "[vvar]")) {
		type = VMA_VVAR;
	} else if (!strcmp(name, "[vdso]")) {
		type = VMA_VDSO;
	} else if (!strcmp(name, "[vsyscall]")) {
		type = VMA_VSYSCALL;
	} else if (!strncmp(basename(name), "lib", 3)) {
		type = VMA_LIB_DONT_KNOWN;
	} else if (strlen(name) == 0) {
		type = VMA_ANON;
	} else {
		type = VMA_NONE;
	}

	return type;
}

struct task {
	pid_t pid;

	// /proc/PID/exe
	char *comm;

	// open(2) /proc/PID/mem
	int proc_mem_fd;
	// open(2) /proc/PID/maps
	int proc_maps_fd;

	struct list_head node;

	// struct vma_struct.node
	struct list_head vmas;
	struct rb_root vmas_rb;
};


int open_pid_maps(pid_t pid);
int open_pid_mem(pid_t pid);

struct vma_struct *next_vma(struct task *task, struct vma_struct *prev);

/* Get task's first vma in rbtree */
#define first_vma(task) next_vma(task, NULL)
/* For each vma of task */
#define task_for_each_vma(vma, task) \
		for (vma = first_vma(task); vma; vma = next_vma(task, vma))

struct vma_struct *find_vma(struct task *task, unsigned long vaddr);
/* Find a span area between two vma */
unsigned long find_vma_span_area(struct task *task, size_t size);

void print_vma(struct vma_struct *vma);
void dump_task_vmas(struct task *task);

struct task *open_task(pid_t pid);
int free_task(struct task *task);

int task_attach(pid_t pid);
int task_detach(pid_t pid);

