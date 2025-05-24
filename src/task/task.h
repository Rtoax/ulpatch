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

#include <task/current.h>
#include <task/flags.h>
#include <task/syscall.h>
#include <task/thread.h>
#include <task/vma.h>

struct vm_area_struct;

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

/* under ULP_PROC_ROOT_DIR/${PID}/ */
#define TASK_PROC_COMM	"comm"
#define TASK_PROC_MAP_FILES	"map_files"

#define TASK_COMM_LEN	128

/**
 * Store values of the auxiliary vector, read from /proc/PID/auxv
 */
struct task_auxv {
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


int open_pid_maps(pid_t pid);
int open_pid_mem_flags(pid_t pid, int flags);
int open_pid_mem_ro(pid_t pid);
int open_pid_mem_rw(pid_t pid);

bool proc_pid_exist(pid_t pid);
const char *proc_pid_exe(pid_t pid, char *buf, size_t bufsz);
const char *proc_pid_cwd(pid_t pid, char *buf, size_t bufsz);
int proc_pid_comm(pid_t pid, char *comm);
int proc_get_pid_status(pid_t pid, struct task_status *status);


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

void print_fd(FILE *fp, struct task_struct *task, struct fd *fd);

int alloc_ulp(struct vm_area_struct *vma);
void free_ulp(struct vm_area_struct *vma);

int load_task_auxv(pid_t pid, struct task_auxv *pauxv);
int print_task_auxv(FILE *fp, const struct task_struct *task);
int print_task_status(FILE *fp, const struct task_struct *task);

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
