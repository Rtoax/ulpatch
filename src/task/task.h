// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
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


enum vma_type {
	VMA_NONE,   /* None */
	VMA_SELF,   /* /usr/bin/ls, ... */
	VMA_LIBC,   /* libc.so.x */
	VMA_HEAP,   /* [heap] */
	VMA_LD,     /* ld-linux-xxxxx */
	VMA_STACK,  /* [stack] */
	VMA_VVAR,   /* [vvar] */
	VMA_VDSO,   /* [vdso] */
	VMA_VSYSCALL, /* [vsyscall] */
	VMA_LIB_UNKNOWN, /* Unknown Library */
	VMA_ANON,   /* No name */
	VMA_ULPATCH,/* ULPatch */
	VMA_TYPE_NUM,
};


struct vm_area_struct;

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

struct vma_ulp {
	struct ulpatch_strtab strtab;
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

	/* struct symbol.node */
	struct rb_root ulp_symbols;
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
	 * If we found the vma is ELF format, open it when open task with PID,
	 * and load all symbol, otherwise, it's NULL.
	 *
	 * FIXME: Use bfd instead, remove this field then.
	 */
	struct elf_file *elf_file;

	/**
	 * If VMA is ELF file, such as the leader of VMA_SELF, VMA_LIBC and
	 * VMA_VDSO, open it as bfd.
	 */
	struct bfd_elf_file *bfd_elf_file;

	/* Only VMA_ULPATCH has it */
	struct vma_ulp *ulp;

	struct task_struct *task;

	/* struct task_struct.vma_list */
	struct list_head node_list;
	/* struct task_struct.vmas_rb */
	struct rb_node node_rb;

	/**
	 * All same name vma in one list, and the first vma is leader.
	 * if vma == vma->leader means that this vma is leader.
	 */
	struct vm_area_struct *leader;
	struct list_head siblings;

	unsigned long voffset;
};

/* see /usr/include/sys/user.h */
#if defined(__x86_64__)
typedef unsigned long long int pc_addr_t;
#elif defined(__aarch64__)
typedef unsigned long long pc_addr_t;
#else
# error Not support architecture
#endif

struct thread {
	pid_t tid;
	/* TODO */
	pc_addr_t ip;
	/* struct task_struct.threads_list */
	struct list_head node;
};

/**
 * Record all file descriptors of target task
 *
 * @fd - read from /proc/PID/fd/
 */
struct fd {
	int fd;
	/* Like /proc/self/fd/0 -> /dev/pts/3 */
	char symlink[PATH_MAX];
	/* struct task_struct.fds_list */
	struct list_head node;
};

/**
 * When task opening, what do you want to do?
 *
 * FTO: Flag of Task when Open.
 */
#define FTO_NONE	0x0
/**
 * Create '/proc' like directory under ULP_PROC_ROOT_DIR. If you need to map a
 * file into target process address space, the flag is necessary.
 */
#define FTO_PROC	BIT(0)
/**
 * This flag will open target process address space's ELF in memory.
 */
#define FTO_VMA_ELF	BIT(1)
/**
 * This flag open /proc/PID/maps specify ELF file.
 */
#define FTO_VMA_ELF_FILE	(BIT(2) | FTO_VMA_ELF)
/**
 * This flag will load all symbols, at same time.
 */
#define FTO_VMA_ELF_SYMBOLS	(BIT(3) | FTO_VMA_ELF | FTO_VMA_ELF_FILE)
/**
 * Open and load /proc/PID/task/, get all target process's thread id.
 */
#define FTO_THREADS	BIT(4)
/**
 * Open task with read and write permission, otherwise readonly.
 */
#define FTO_RDWR	BIT(5)
/**
 * Open /proc/PID/fd/ directory and for each FD.
 */
#define FTO_FD		BIT(6)

#define FTO_ALL 0xffffffff

#define FTO_ULFTRACE	(FTO_PROC | \
			FTO_VMA_ELF_SYMBOLS | \
			FTO_THREADS | \
			FTO_RDWR | \
			FTO_FD)
#define FTO_ULPATCH	FTO_ULFTRACE

/* under ULP_PROC_ROOT_DIR/${PID}/ */
#define TASK_PROC_COMM	"comm"
#define TASK_PROC_MAP_FILES	"map_files"

#define TASK_COMM_LEN	128

/**
 * Store values of the auxiliary vector, read from /proc/PID/auxv
 */
struct task_struct_auxv {
	/* AT_PHDR */
	unsigned long auxv_phdr;
	/* AT_PHENT */
	unsigned long auxv_phent;
	/* AT_PHNUM */
	unsigned long auxv_phnum;
	/* AT_BASE */
	unsigned long auxv_interp;
	/* AT_ENTRY */
	unsigned long auxv_entry;
};

struct task_status {
	/**
	 * Get from /proc/[pid]/status
	 */
	uid_t uid, euid, suid, fsuid;
	gid_t gid, egid, sgid, fsgid;
};

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
	char *exe;

	bool is_pie;

	struct task_struct_auxv auxv;
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

	/* struct thread.node */
	struct list_head threads_list;

	/* struct fd.node */
	struct list_head fds_list;
};


int open_pid_maps(pid_t pid);
int __open_pid_mem(pid_t pid, int flags);
int open_pid_mem_ro(pid_t pid);
int open_pid_mem_rw(pid_t pid);

bool proc_pid_exist(pid_t pid);
char *get_proc_pid_exe(pid_t pid, char *buf, size_t bufsz);

struct vm_area_struct *next_vma(struct task_struct *task, struct vm_area_struct *prev);

/* Get task's first vma in rbtree */
#define first_vma(task) next_vma(task, NULL)
/* For each vma of task */
#define task_for_each_vma(vma, task) \
	for (vma = first_vma(task); vma; vma = next_vma(task, vma))

struct vm_area_struct *alloc_vma(struct task_struct *task);
void insert_vma(struct task_struct *task, struct vm_area_struct *vma,
		struct vm_area_struct *prev);
void unlink_vma(struct task_struct *task, struct vm_area_struct *vma);
void free_vma(struct vm_area_struct *vma);

struct vm_area_struct *find_vma(const struct task_struct *task,
				unsigned long vaddr);
struct vm_area_struct *next_vma(struct task_struct *task,
				struct vm_area_struct *prev);

enum vma_type get_vma_type(pid_t pid, const char *exe, const char *name);

/* Find a span area between two vma */
unsigned long find_vma_span_area(struct task_struct *task, size_t size,
				 unsigned long base);
int read_task_vmas(struct task_struct *task, bool update_ulp);
int update_task_vmas_ulp(struct task_struct *task);
int free_task_vmas(struct task_struct *task);

int dump_task(const struct task_struct *t, bool detail);

void dump_task_vmas(struct task_struct *task, bool detail);
int dump_task_addr_to_file(const char *ofile, struct task_struct *task,
		unsigned long addr, unsigned long size);
int dump_task_vma_to_file(const char *ofile, struct task_struct *task,
		unsigned long addr);
void dump_task_threads(struct task_struct *task, bool detail);
void dump_task_fds(struct task_struct *task, bool detail);

int __prot2flags(unsigned int prot);
unsigned int __perms2prot(char *perms);

bool elf_vma_is_interp_exception(struct vm_area_struct *vma);

const char *vma_type_name(enum vma_type type);
void print_vma(FILE *fp, bool first_line, struct vm_area_struct *vma, bool detail);
void print_thread(FILE *fp, struct task_struct *task, struct thread *thread);
void print_fd(FILE *fp, struct task_struct *task, struct fd *fd);

int alloc_ulp(struct vm_area_struct *vma);
void free_ulp(struct vm_area_struct *vma);

int load_task_auxv(pid_t pid, struct task_struct_auxv *pauxv);
int print_task_auxv(FILE *fp, const struct task_struct *task);

int load_task_status(pid_t pid, struct task_status *status);
int print_task_status(FILE *fp, const struct task_struct *task);

#define current get_current_task()
#define zero_task __zero_task()
int set_current_task(struct task_struct *task);
void reset_current_task(void);
struct task_struct *const get_current_task(void);
struct task_struct *const __zero_task(void);

struct task_struct *open_task(pid_t pid, int flag);
int close_task(struct task_struct *task);
void print_task(FILE *fp, const struct task_struct *task, bool detail);
bool task_is_pie(struct task_struct *task);

int task_attach(pid_t pid);
int task_detach(pid_t pid);

int memcpy_to_task(struct task_struct *task,
		unsigned long remote_dst, void *src, ssize_t size);
int memcpy_from_task(struct task_struct *task,
		void *dst, unsigned long remote_src, ssize_t size);
char *strcpy_from_task(struct task_struct *task, char *dst,
		       unsigned long task_src);
char *strcpy_to_task(struct task_struct *task, unsigned long task_dst,
		     char *src);

/* syscalls based on task_syscall() */
/* if mmap file, need to update_task_vmas_ulp() manual */
unsigned long task_mmap(struct task_struct *task,
	unsigned long addr, size_t length, int prot, int flags,
	int fd, off_t offset);
int task_munmap(struct task_struct *task, unsigned long addr, size_t size);
int task_msync(struct task_struct *task, unsigned long addr, size_t length, int flags);
int task_msync_sync(struct task_struct *task, unsigned long addr, size_t length);
int task_msync_async(struct task_struct *task, unsigned long addr, size_t length);
unsigned long task_malloc(struct task_struct *task, size_t length);
int task_free(struct task_struct *task, unsigned long addr, size_t length);
int task_open(struct task_struct *task, char *pathname, int flags, mode_t mode);
int task_close(struct task_struct *task, int remote_fd);
int task_ftruncate(struct task_struct *task, int remote_fd, off_t length);
int task_fstat(struct task_struct *task, int remote_fd, struct stat *statbuf);
int task_prctl(struct task_struct *task, int option, unsigned long arg2,
	unsigned long arg3, unsigned long arg4, unsigned long arg5);

/* Execute a syscall(2) in target task */
int task_syscall(struct task_struct *task, int nr,
		unsigned long arg1, unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5, unsigned long arg6,
		unsigned long *res);

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

