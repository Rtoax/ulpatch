// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
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
#include <task/task.h>

#if defined(__x86_64__)
#include <arch/x86_64/regs.h>
#include <arch/x86_64/instruments.h>
#elif defined(__aarch64__)
#include <arch/aarch64/regs.h>
#include <arch/aarch64/instruments.h>
#endif

struct vm_area_struct *alloc_vma(struct task_struct *task)
{
	struct vm_area_struct *vma;

	vma = malloc(sizeof(struct vm_area_struct));
	if (!vma) {
		ulp_error("Malloc vma failed.\n");
		return NULL;
	}
	memset(vma, 0x00, sizeof(struct vm_area_struct));

	vma->task = task;
	vma->type = VMA_NONE;
	vma->leader = NULL;
	vma->ulp = NULL;

	list_init(&vma->node_list);
	list_init(&vma->siblings);

	return vma;
}

static inline int __vma_rb_cmp(struct rb_node *node, unsigned long key)
{
	struct vm_area_struct *vma;
	struct vm_area_struct *new = (struct vm_area_struct *)key;

	vma = rb_entry(node, struct vm_area_struct, node_rb);

	if (new->vm_end <= vma->vm_start)
		return -1;
	else if (vma->vm_start < new->vm_end && vma->vm_end > new->vm_start)
		return 0;
	else if (vma->vm_end <= new->vm_start)
		return 1;

	print_vma(stdout, true, vma, true);
	ulp_error("Try to insert illegal vma, see above dump vma.\n");
	return 0;
}

void insert_vma(struct task_struct *task, struct vm_area_struct *vma,
		struct vm_area_struct *prev)
{
	if (prev && strcmp(prev->name_, vma->name_) == 0) {
		struct vm_area_struct *leader = prev->leader;
		vma->leader = leader;
		list_add(&vma->siblings, &leader->siblings);
	}

	list_add(&vma->node_list, &task->vma_list);
	rb_insert_node(&task->vmas_rb, &vma->node_rb, __vma_rb_cmp,
			(unsigned long)vma);
}

void unlink_vma(struct task_struct *task, struct vm_area_struct *vma)
{
	list_del(&vma->node_list);
	rb_erase(&vma->node_rb, &task->vmas_rb);
	list_del(&vma->siblings);
}

void free_vma(struct vm_area_struct *vma)
{
	if (!vma)
		return;
	free_ulp(vma);
	free(vma);
}

static inline int __find_vma_cmp(struct rb_node *node, unsigned long vaddr)
{
	struct vm_area_struct *vma;

	vma = rb_entry(node, struct vm_area_struct, node_rb);

	if (vma->vm_start > vaddr)
		return -1;
	else if (vma->vm_start <= vaddr && vma->vm_end > vaddr)
		return 0;
	else
		return 1;
}

struct vm_area_struct *find_vma(const struct task_struct *task,
				unsigned long vaddr)
{
	struct rb_node *rnode;
	rnode = rb_search_node((struct rb_root *)&task->vmas_rb,
			       __find_vma_cmp, vaddr);
	if (rnode)
		return rb_entry(rnode, struct vm_area_struct, node_rb);
	errno = ENOENT;
	return NULL;
}

struct vm_area_struct *next_vma(struct task_struct *task,
				struct vm_area_struct *prev)
{
	struct rb_node *next;
	next = prev ? rb_next(&prev->node_rb) : rb_first(&task->vmas_rb);
	return  next ? rb_entry(next, struct vm_area_struct, node_rb) : NULL;
}

unsigned long find_vma_span_area(struct task_struct *task, size_t size,
				 unsigned long base)
{
	struct vm_area_struct *ivma, *first_vma, *next_vma;
	struct rb_node *first, *next, *rnode;

	first = rb_first(&task->vmas_rb);
	first_vma = rb_entry(first, struct vm_area_struct, node_rb);

	/**
	 * Start from base if base non-zero.
	 */
	if (base && base >= MIN_ULP_START_VMA_ADDR &&
	    first_vma->vm_start > base &&
	    first_vma->vm_start - base >= size)
		return base;

	/**
	 * For each vma to find span area.
	 */
	for (rnode = first; rnode; rnode = rb_next(rnode)) {
		ivma = rb_entry(rnode, struct vm_area_struct, node_rb);
		next = rb_next(rnode);
		if (!next)
			return 0;

		ulp_debug("vma: %lx-%lx %s\n", ivma->vm_start, ivma->vm_end,
			ivma->name_);

		next_vma = rb_entry(next, struct vm_area_struct, node_rb);
		if (next_vma->vm_start - ivma->vm_end >= size)
			return ivma->vm_end;
	}
	ulp_error("No space fatal in target process, pid %d\n", task->pid);
	return 0;
}

unsigned int vma_perms2prot(char *perms)
{
	unsigned int prot = PROT_NONE;

	if (perms[0] == 'r')
		prot |= PROT_READ;
	if (perms[1] == 'w')
		prot |= PROT_WRITE;
	if (perms[2] == 'x')
		prot |= PROT_EXEC;
	/* Ignore 'p'/'s' flag, we don't need it */
	return prot;
}

int vma_prot2flags(unsigned int prot)
{
	unsigned int flags = 0;

	flags |= (prot & PROT_READ) ? PF_R : 0;
	flags |= (prot & PROT_WRITE) ? PF_W : 0;
	flags |= (prot & PROT_EXEC) ? PF_X : 0;

	return flags;
}

int free_task_vmas(struct task_struct *task);

enum vma_type get_vma_type(pid_t pid, const char *exe, const char *name)
{
	enum vma_type type = VMA_NONE;
	char s_pid[64];

	snprintf(s_pid, sizeof(s_pid), "%d", pid);

	if (!strcmp(name, exe)) {
		type = VMA_SELF;
	/**
	 * FIXME: What if has libc-just-test.so dynamic library?
	 */
	} else if (!strncmp(basename((char*)name), "libc.so", 7) ||
		   !strncmp(basename((char*)name), "libssp", 6) ||
		   !strncmp(basename((char*)name), "libc-", 5)) {
		type = VMA_LIBC;
	} else if (!strcmp(name, "[heap]")) {
		type = VMA_HEAP;
	} else if (!strncmp(basename((char*)name), "ld-linux", 8)) {
		type = VMA_LD;
	} else if (!strcmp(name, "[stack]")) {
		type = VMA_STACK;
	} else if (!strcmp(name, "[uprobes]")) {
		type = VMA_UPROBES;
	} else if (!strcmp(name, "[vvar]")) {
		type = VMA_VVAR;
	} else if (!strcmp(name, "[vvar_vclock]")) {
		type = VMA_VVAR_VCLOCK;
	} else if (!strcmp(name, "[vdso]")) {
		type = VMA_VDSO;
	} else if (!strcmp(name, "[vsyscall]")) {
		type = VMA_VSYSCALL;
	} else if (!strncmp(basename((char*)name), "lib", 3) &&
		   strstr(name, ".so")) {
		type = VMA_LIB_UNKNOWN;
	} else if (strlen(name) == 0) {
		type = VMA_ANON;
	/**
	 * Example:
	 * /tmp/ulpatch/20298/map_files/ulp-GLpgJM
	 *              ^^^^^           ^^^^
	 */
	} else if (strstr(name, PATCH_VMA_TEMP_PREFIX) &&
		   strstr(name, s_pid)) {
		type = VMA_ULPATCH;
	} else {
		type = VMA_NONE;
	}

	return type;
}

static const struct {
	enum vma_type type;
	const char *name;
} __vma_type_names[] = {
	{VMA_NONE, "unknown"},
	{VMA_SELF, "self"},
	{VMA_LIBC, "libc"},
	{VMA_HEAP, "heap"},
	{VMA_LD, "ld"},
	{VMA_STACK, "stack"},
	{VMA_UPROBES, "uprobes"},
	{VMA_VVAR, "vvar"},
	{VMA_VVAR_VCLOCK, "vvar_vclock"},
	{VMA_VDSO, "vdso"},
	{VMA_VSYSCALL, "vsyscall"},
	{VMA_LIB_UNKNOWN, "lib?"},
	{VMA_ANON, "anon"},
	{VMA_ULPATCH, "ulpatch"},
};

const char *vma_type_name(enum vma_type type)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(__vma_type_names); i++)
		if (__vma_type_names[i].type == type)
			return __vma_type_names[i].name;
	return "Unknown";
}

bool elf_vma_is_interp_exception(struct vm_area_struct *vma)
{
	char *name = vma->name_;

	/* libc */
	if (!strncmp(name, "libc", 4) &&
	    !strncmp(name + strlen(name) - 3, ".so", 3))
		return true;

	/**
	 * some times, libc-xxx.so(like libssp.so.0) is linked to libssp.so.xx
	 */
	if (!strncmp(name, "libssp", 6)) {
		return true;
	}

	/* libpthread */
	if (!strncmp(name, "libpthread", 10) &&
	    !strncmp(name + strlen(name) - 3, ".so", 3))
		return true;

	/* libdl */
	if (!strncmp(name, "libdl", 5) &&
	    !strncmp(name + strlen(name) - 3, ".so", 3))
		return true;

	return false;
}

/**
 * @update_ulp: if patch to target process, we need to insert the new vma to
 *              list.
 */
int read_task_vmas(struct task_struct *task, bool update_ulp)
{
	struct vm_area_struct *vma, *prev = NULL;
	int mapsfd;
	FILE *mapsfp;

	/* open(2) /proc/[PID]/maps */
	mapsfd = open_pid_maps(task->pid);
	if (mapsfd <= 0)
		return -errno;
	lseek(mapsfd, 0, SEEK_SET);

	mapsfp = fdopen(mapsfd, "r");
	fseek(mapsfp, 0, SEEK_SET);
	do {
		unsigned long start, end, off;
		unsigned int major, minor;
		unsigned long inode;
		char perms[5], name_[256];
		int r;
		char line[1024];
		struct vm_area_struct __unused *old;

		start = end = off = major = minor = inode = 0;

		memset(perms, 0, sizeof(perms));
		memset(name_, 0, sizeof(name_));
		memset(line, 0, sizeof(line));

		if (!fgets(line, sizeof(line), mapsfp))
			break;

		r = sscanf(line, "%lx-%lx %s %lx %x:%x %ld %255s", &start,
			   &end, perms, &off, &major, &minor, &inode, name_);
		if (r <= 0) {
			ulp_error("sscanf failed.\n");
			return -1;
		}
#if 1
		if (update_ulp) {
			old = find_vma(task, start + 1);
			/* Skip if alread exist. */
			if (old && old->vm_start == start &&
			    old->vm_end == end) {
				ulp_warning("vma %s alread exist.\n", name_);
				continue;
			} else
				ulp_warning("insert vma %s.\n", name_);
		}
#endif

		vma = alloc_vma(task);

		vma->vm_start = start;
		vma->vm_end = end;
		memcpy(vma->perms, perms, sizeof(vma->perms));
		vma->prot = vma_perms2prot(perms);
		vma->vm_pgoff = (off >> PAGE_SHIFT);
		vma->major = major;
		vma->minor = minor;
		vma->inode = inode;
		strncpy(vma->name_, name_, sizeof(vma->name_));
		vma->type = get_vma_type(task->pid, task->exe, name_);

		/* Find libc.so */
		if (!task->libc_vma && vma->type == VMA_LIBC &&
		    vma->prot & PROT_EXEC) {
			ulp_debug("Get x libc: 0x%lx\n", vma->vm_start);
			task->libc_vma = vma;
		}

		/* Find [stack] */
		if (!task->stack && vma->type == VMA_STACK)
			task->stack = vma;

		vma->leader = vma;

		insert_vma(task, vma, prev);
		prev = vma;
	} while (1);

	fclose(mapsfp);
	close(mapsfd);
	return 0;
}

void print_vma(FILE *fp, bool first_line, struct vm_area_struct *vma,
	       bool detail)
{
	int i;

	if (!vma) {
		ulp_error("Invalide pointer.\n");
		return;
	}

	fp = fp ?: stdout;

	if (first_line) {
		fprintf(fp, "%10s: %16s %16s %6s %4s\n",
			"TYPE", "Start", "End", "Perm", "Role");
		fprintf(fp, "%11s %16s %16s %s\n",
			"", "off", "Voffset", "Name");
	}

	fprintf(fp, "%10s: %016lx-%016lx %6s %s%s%s%s\n",
		vma_type_name(vma->type),
		vma->vm_start,
		vma->vm_end,
		vma->perms,
		vma->is_elf ? "E" : "-",
		vma->is_share_lib ? "S" : "-",
		vma->is_matched_phdr ? "P" : "-",
		vma->leader == vma ? "L" : "-");
	fprintf(fp, "%11s %016lx %016lx %s\n",
		"",
		vma->vm_pgoff << PAGE_SHIFT,
		vma->voffset,
		vma->name_);

	if (detail) {
		/* Detail with gray color */
		if (fp == stdout || fp == stderr)
			fprintf(fp, "\033[2m");
		if (vma->vma_elf) {
			fprintf(fp, "%10s  load_addr = 0x%lx\n", "",
				vma->vma_elf->load_addr);
			bool first = true;
			print_ehdr(fp, &vma->vma_elf->ehdr);
			for (i = 0; i < vma->vma_elf->ehdr.e_phnum; i++) {
				GElf_Phdr *pphdr = &vma->vma_elf->phdrs[i];
				if (pphdr->p_type != PT_LOAD)
					continue;
				print_phdr(fp, NULL, pphdr, first);
				first = false;
			}
		}
		if (vma->is_matched_phdr)
			print_phdr(fp, NULL, &vma->phdr, true);
		/* Add more information here */
		if (fp == stdout || fp == stderr)
			fprintf(fp, "\033[0m");
	}
}
