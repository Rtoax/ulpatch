// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
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

#include <elf/elf_api.h>

#include <utils/log.h>
#include <utils/task.h>

#if defined(__x86_64__)
#include <arch/x86_64/regs.h>
#include <arch/x86_64/instruments.h>
#elif defined(__aarch64__)
#include <arch/aarch64/regs.h>
#include <arch/aarch64/instruments.h>
#endif


int open_pid_maps(pid_t pid)
{
	int mapsfd;
	char maps[] = "/proc/1234567890/maps";

	snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
	mapsfd = open(maps, O_RDONLY);
	if (mapsfd <= 0) {
		lerror("open %s failed. %s\n", maps, strerror(errno));
		mapsfd = -1;
	}
	return mapsfd;
}

int fprint_pid_maps(FILE *fp, int mapsfd)
{
	char ch;
	int cnt = 0;

	if (fp == NULL)
		fp = stdout;

	while (read(mapsfd, &ch, 1) == 1) {
		fputc(ch, fp);
		cnt++;
	}
	return cnt;
}

static int __open_pid_mem(pid_t pid, int flags)
{
	char mem[] = "/proc/1234567890/mem";
	snprintf(mem, sizeof(mem), "/proc/%d/mem", pid);
	int memfd = open(mem, flags);
	if (memfd <= 0) {
		lerror("open %s failed. %s\n", mem, strerror(errno));
		memfd = -errno;
	}
	return memfd;
}

int open_pid_mem_ro(pid_t pid)
{
	return __open_pid_mem(pid, O_RDONLY);
}

int open_pid_mem_rw(pid_t pid)
{
	return __open_pid_mem(pid, O_RDWR);
}

static struct vm_area_struct *alloc_vma(struct task_struct *task)
{
	struct vm_area_struct *vma;

	vma = malloc(sizeof(struct vm_area_struct));
	if (!vma) {
		lerror("Malloc vma failed.\n");
		return NULL;
	}
	memset(vma, 0x00, sizeof(struct vm_area_struct));

	vma->task = task;
	vma->type = VMA_NONE;

	list_init(&vma->node_list);

	vma->leader = NULL;
	vma->ulp = NULL;

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
	lerror("Try to insert illegal vma, see above dump vma.\n");
	return 0;
}

static void insert_vma(struct task_struct *task, struct vm_area_struct *vma,
		       struct vm_area_struct *prev)
{
	if (prev && strcmp(prev->name_, vma->name_) == 0) {
		struct vm_area_struct *leader = prev->leader;
		vma->leader = leader;
		list_add(&vma->siblings, &leader->siblings);
	}

	list_add(&vma->node_list, &task->vma_list);
	rb_insert_node(&task->vmas_rb, &vma->node_rb,
		__vma_rb_cmp, (unsigned long)vma);
}

static void unlink_vma(struct task_struct *task, struct vm_area_struct *vma)
{
	list_del(&vma->node_list);
	rb_erase(&vma->node_rb, &task->vmas_rb);
	list_del(&vma->siblings);
}

static void free_vma(struct vm_area_struct *vma)
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
	return NULL;
}

struct vm_area_struct *next_vma(struct task_struct *task,
				struct vm_area_struct *prev)
{
	struct rb_node *next;
	next = prev ? rb_next(&prev->node_rb) : rb_first(&task->vmas_rb);
	return  next ? rb_entry(next, struct vm_area_struct, node_rb) : NULL;
}

unsigned long find_vma_span_area(struct task_struct *task, size_t size)
{
	struct vm_area_struct *ivma, *first_vma;
	struct rb_node *first, *rnode;

	first = rb_first(&task->vmas_rb);
	first_vma = rb_entry(first, struct vm_area_struct, node_rb);

	/**
	 * Return the minimal address if the space is enough to store 'size'.
	 */
	if (first_vma->vm_start > MIN_ULP_START_VMA_ADDR &&
	    first_vma->vm_start - MIN_ULP_START_VMA_ADDR >= size)
		return MIN_ULP_START_VMA_ADDR;

	for (rnode = first; rnode; rnode = rb_next(rnode)) {
		ivma = rb_entry(rnode, struct vm_area_struct, node_rb);
		struct rb_node *next_node = rb_next(rnode);
		struct vm_area_struct *next_vma;
		if (!next_node)
			return 0;

		ldebug("vma: %lx-%lx %s\n", ivma->vm_start, ivma->vm_end,
			ivma->name_);

		next_vma = rb_entry(next_node, struct vm_area_struct, node_rb);
		if (next_vma->vm_start - ivma->vm_end >= size)
			return ivma->vm_end;
	}
	lerror("No space fatal in target process, pid %d\n", task->pid);
	return 0;
}

static unsigned int __perms2prot(char *perms)
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

static int __prot2flags(unsigned int prot)
{
	unsigned int flags = 0;

	flags |= (prot & PROT_READ) ? PF_R : 0;
	flags |= (prot & PROT_WRITE) ? PF_W : 0;
	flags |= (prot & PROT_EXEC) ? PF_X : 0;

	return flags;
}

int free_task_vmas(struct task_struct *task);

static enum vma_type get_vma_type(pid_t pid, const char *exe, const char *name)
{
	enum vma_type type = VMA_NONE;
	char s_pid[64];

	snprintf(s_pid, sizeof(s_pid), "%d", pid);

	if (!strcmp(name, exe)) {
		type = VMA_SELF;
	} else if (!strncmp(basename((char*)name), "libc.so", 7)
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
	/**
	 * Example:
	 * /tmp/ulpatch/17099/map_files/patch-ZUkaOS
	 *              ^^^^^           ^^^^^^
	 */
	} else if (strstr(name, PATCH_VMA_TEMP_PREFIX) && strstr(name, s_pid)) {
		type = VMA_ULPATCH;
	} else {
		type = VMA_NONE;
	}

	return type;
}

static bool elf_vma_is_interp_exception(struct vm_area_struct *vma)
{
	char *name = vma->name_;

	/* libc */
	if (!strncmp(name, "libc", 4) &&
	    !strncmp(name + strlen(name) - 3, ".so", 3))
		return true;

	/* some times, libc-xxx.so(like libssp.so.0) is linked to libssp.so.xx  */
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
 * data vma will splited by linker(GNU linker ld) according to PT_GNU_RELRO,
 * see ".data.rel.ro" section, which in the last PT_LOAD and has single PHDR.
 * at the same time, it's in PT_GNU_RELRO, which will be set to readonly by
 * GNU Linker by mprotect(2) syscall.
 */
static int _relro_dl_mprotect(struct vm_area_struct *vma, GElf_Phdr *phdr,
			      unsigned long load_addr, GElf_Phdr *relro_phdr)
{
	int ret = 0;
	unsigned long start, end;

	struct range {
		unsigned long start, end;
	} range[2];

	if (!relro_phdr)
		return 0;

	start = PAGE_DOWN(load_addr + relro_phdr->p_vaddr);
	end = PAGE_DOWN(load_addr + relro_phdr->p_vaddr + relro_phdr->p_memsz);

	/**
	 * This is PT_GNU_RELRO VMA
	 */
	range[0].start = start;
	range[0].end = end;
	/**
	 * This is the last PT_LOAD, who splited by GNU linker
	 * _dl_protect_relro() function. Current vma will match to this range.
	 */
	range[1].start = end;
	range[1].end = vma->vm_end;

#if 0
	ret |= (range[0].start == vma->vm_start) &&
		(range[0].end == vma->vm_end);
#endif
	ret |= (range[1].start == vma->vm_start) &&
		(range[1].end == vma->vm_end);

	return ret;
}

/**
 * Match VMA with PT_LOAD
 */
static int match_vma_phdr(struct vm_area_struct *vma, GElf_Phdr *phdr,
			  unsigned long load_addr, GElf_Phdr *relro_phdr)
{
	int ret = 0;
	unsigned long addr, size, off;

	addr = load_addr + phdr->p_vaddr;
	size = phdr->p_filesz + ELF_PAGEOFFSET(phdr->p_vaddr);
	off = phdr->p_offset - ELF_PAGEOFFSET(phdr->p_vaddr);

	addr = ELF_PAGESTART(addr);
	size = ELF_PAGEALIGN(size);
	/* also check off? */
	(void)off;

	ret = (addr == vma->vm_start) && (addr + size == vma->vm_end) &&
		((phdr->p_flags & (PF_R | PF_W | PF_X)) == __prot2flags(vma->prot));

	ldebug("MatchPhdr: %lx-%lx vs %lx-%lx "PROT_FMT" ret=%d\n",
		addr, addr + size, vma->vm_start, vma->vm_end,
		PROT_ARGS(vma->prot), ret);

	/**
	 * If has PT_GNU_RELRO(".data.rel.ro" in it), the GNU linker will
	 * set PT_GNU_RELRO to readonly in _dl_protect_relro() function.
	 * At the same time, ".data.rel.ro" in the last PT_LOAD too.
	 */
	if (!ret && phdr->p_type == PT_LOAD && relro_phdr)
		ret = _relro_dl_mprotect(vma, phdr, load_addr, relro_phdr);

	if (ret) {
		vma->is_matched_phdr = true;
		memcpy(&vma->phdr, phdr, sizeof(vma->phdr));
	}

	return ret;
}

int alloc_ulp(struct vm_area_struct *vma)
{
	int ret;
	void *mem;
	struct vma_ulp *ulp;
	size_t elf_mem_len = vma->vm_end - vma->vm_start;
	struct task_struct *task = vma->task;

	ulp = malloc(sizeof(struct vma_ulp));
	if (!ulp) {
		lerror("malloc failed.\n");
		return -ENOMEM;
	}
	mem = malloc(elf_mem_len);
	if (!mem) {
		lerror("malloc failed.\n");
		return -ENOMEM;
	}

	vma->ulp = ulp;
	ulp->elf_mem = mem;
	ulp->vma = vma;
	ulp->str_build_id = NULL;
	rb_init(&ulp->ulp_symbols);

	/* Copy VMA from target task memory space */
	ret = memcpy_from_task(task, ulp->elf_mem, vma->vm_start, elf_mem_len);
	if (ret == -1 || ret < elf_mem_len) {
		lerror("Failed read from %lx:%s\n", vma->vm_start, vma->name_);
		free_ulp(vma);
		return -EAGAIN;
	}

	ldebug("Add %s to ulpatch list.\n", vma->name_);
	list_add(&ulp->node, &task->ulp_list);
	return 0;
}

void free_ulp(struct vm_area_struct *vma)
{
	struct vma_ulp *ulp = vma->ulp;

	if (!ulp)
		return;

	ldebug("Remove %s from ulpatch list.\n", vma->name_);

	list_del(&ulp->node);
	if (ulp->str_build_id)
		free(ulp->str_build_id);

	/* Destroy symbols rb tree */
	rb_destroy(&ulp->ulp_symbols, rb_free_symbol);

	free(ulp->elf_mem);
	free(ulp);
	vma->ulp = NULL;
}

int vma_load_ulp(struct vm_area_struct *vma)
{
	int ret;
	GElf_Ehdr ehdr = {};
	struct task_struct *task = vma->task;
	struct load_info info = {
		.target_task = task,
	};

	ldebug("Load ulpatch vma %s.\n", vma->name_);

	ret = memcpy_from_task(task, &ehdr, vma->vm_start, sizeof(ehdr));
	if (ret == -1 || ret < sizeof(ehdr)) {
		lerror("Failed read from %lx:%s\n", vma->vm_start, vma->name_);
		return -EAGAIN;
	}

	if (!ehdr_magic_ok(&ehdr)) {
		lerror("VMA %s(%lx) is considered as ULPATCH, but it isn't ELF.",
			vma->name_, vma->vm_start);
		return -ENOENT;
	}

	vma->is_elf = true;
	alloc_ulp(vma);
	vma_load_ulp_info(vma, &info);

	if (task->max_ulp_id < info.ulp_info->ulp_id)
		task->max_ulp_id = info.ulp_info->ulp_id;

	return 0;
}

/* Only FTO_VMA_ELF flag will load VMA ELF */
int vma_peek_phdr(struct vm_area_struct *vma)
{
	GElf_Ehdr ehdr = {};
	struct task_struct *task = vma->task;
	unsigned long phaddr;
	unsigned int phsz = 0;
	int ret;
	int i;
	bool is_share_lib = true;
	unsigned long lowest_vaddr = ULONG_MAX;
	GElf_Phdr *gnu_relro_phdr = NULL;

	/* Check VMA type, and skip it */
	switch (vma->type) {
	case VMA_VVAR:
	case VMA_STACK:
	case VMA_VSYSCALL:
		lwarning("skip %s\n", VMA_TYPE_NAME(vma->type));
		return 0;
	case VMA_ULPATCH:
		return vma_load_ulp(vma);
	default:
		break;
	}

	/* Just skip already peeked ELF */
	if (vma->vma_elf != NULL || vma->is_elf)
		return 0;

	/**
	 * Add more check here, skip some VMA peek, because some vma pread()
	 * will failed, and it's not necessary to check is ELF or not.
	 */
	if (!strncmp(vma->name_, "/etc", 4) ||
	    !strncmp(vma->name_, "/sys", 4)) {
		ldebug("Skip peek vma %s\n", vma->name_);
		return 0;
	}

	ldebug("Peek a phdr from %s, addr %lx\n", vma->name_, vma->vm_start);

	/**
	 * Read the ELF header from target task memory.
	 */
	ret = memcpy_from_task(task, &ehdr, vma->vm_start, sizeof(ehdr));
	if (ret < sizeof(ehdr)) {
		lerror("Failed read from %lx:%s\n", vma->vm_start, vma->name_);
		return -EAGAIN;
	}

	/* If it's not ELF, return success, skip the non-ELF VMAs */
	if (!ehdr_ok(&ehdr))
		return 0;

	ldebug("%lx %s is ELF\n", vma->vm_start, vma->name_);

	if (vma->type == VMA_SELF) {
		task->vma_self_elf = vma;
		/**
		 * Executable file only could be ET_EXEC or ET_DYN, if ET_DYN,
		 * the ELF was compiled with -fPIE, and it's PIE executable
		 * ELF file.
		 *
		 * You could see binutils [0] binutils/readelf.c::is_pie()
		 * function implement.
		 *
		 * [0] https://sourceware.org/git/binutils-gdb.git
		 */
		if (ehdr.e_type == ET_DYN) {
			ldebug("%s is PIE.\n", vma->name_);
			task->is_pie = true;
		}  else {
			ldebug("%s is not PIE.\n", vma->name_);
			task->is_pie = false;
		}
	}

	/* VMA is ELF, handle it */
	vma->vma_elf = malloc(sizeof(struct vma_elf_mem));
	if (!vma->vma_elf)
		return -ENOMEM;

	memset(vma->vma_elf, 0x00, sizeof(struct vma_elf_mem));

	/* Copy ehdr from load var */
	memcpy(&vma->vma_elf->ehdr, &ehdr, sizeof(ehdr));

	phaddr = vma->vm_start + vma->vma_elf->ehdr.e_phoff;
	phsz = vma->vma_elf->ehdr.e_phnum * sizeof(GElf_Phdr);

	/**
	 * If no program headers, just return. we don't need it, such as:
	 * /usr/lib64/ld-linux-x86-64.so.2 has '.ELF' magic, but it's no phdr.
	 */
	if (phsz == 0) {
		lwarning("%s: no phdr, e_phoff %lx, skip it.\n",
			 vma->name_, vma->vma_elf->ehdr.e_phoff);
		free(vma->vma_elf);
		return 0;
	}

	vma->vma_elf->phdrs = malloc(phsz);
	if (!vma->vma_elf->phdrs) {
		free(vma->vma_elf);
		return -ENOMEM;
	}

	/* Read all program headers from target task memory space */
	ldebug("peek phdr from target addr %lx, len %d\n", phaddr, phsz);
	if (memcpy_from_task(task, vma->vma_elf->phdrs, phaddr, phsz) < phsz) {
		free(vma->vma_elf->phdrs);
		free(vma->vma_elf);
		lerror("Failed to read %s program header.\n", vma->name_);
		return -EAGAIN;
	}

	vma->is_elf = true;

	/**
	 * "[vdso]" vma is elf, but file is not exist, could not open it.
	 */
	if (task->fto_flag & FTO_VMA_ELF_FILE && fexist(vma->name_)) {
		vma->elf_file = elf_file_open(vma->name_);
		if (!vma->elf_file) {
			lerror("Open ELF %s failed.\n", vma->name_);
			return -EINVAL;
		}
		switch (vma->type) {
		case VMA_SELF:
			task->exe_elf = vma->elf_file;
			break;
		case VMA_LIBC:
			task->libc_elf = vma->elf_file;
			break;
		default:
			break;
		}
	}

	/**
	 * If type of the ELF is not ET_DYN, this is definitely not a shared
	 * library.
	 *
	 * Actually, if the executable file is compiled with '-fPIE'(Position-
	 * Independent Executable file), it's ET_DYN too.
	 */
	if (vma->vma_elf->ehdr.e_type != ET_DYN) {
		is_share_lib = false;
		goto share_lib;
	}

	/**
	 * Now there are possibilities:
	 *   - either this is really a shared library
	 *   - or this is a position-independent executable
	 * To distinguish between them look for INTERP
	 * program header that mush be present in any valid
	 * executable or usually don't in shared libraries
	 * (notable exception - libc)
	 */
	for (i = 0; i < vma->vma_elf->ehdr.e_phnum; i++) {
		/* Ok, looks like this is an executable */
		if (vma->vma_elf->phdrs[i].p_type == PT_INTERP &&
			!elf_vma_is_interp_exception(vma)) {
			is_share_lib = false;
			goto share_lib;
		}
	}

share_lib:

	is_share_lib |= vma->type == VMA_LIBC;
	is_share_lib |= vma->type == VMA_LIB_DONT_KNOWN;

	vma->is_share_lib = is_share_lib;

	/**
	 * VMA is ELF, for each program header to find the lowest Virtual
	 * address in p_vaddr.
	 */
	for (i = 0; i < vma->vma_elf->ehdr.e_phnum; i++) {
		GElf_Phdr *phdr = &vma->vma_elf->phdrs[i];
		unsigned long vaddr;
		struct vm_area_struct *sibling, *tmpvma;

		switch (phdr->p_type) {
		case PT_LOAD:
			lowest_vaddr = lowest_vaddr <= phdr->p_vaddr
					? lowest_vaddr : phdr->p_vaddr;

			ldebug("PT_LOAD: %s, lowest_vaddr %lx\n", vma->name_,
				lowest_vaddr);

			/* Virtual address offset */
			vaddr = ALIGN_DOWN(phdr->p_vaddr, phdr->p_align);

			list_for_each_entry_safe(sibling, tmpvma,
				&vma->siblings, siblings) {

				/* Ignore vma holes, ---p */
				if (vma->prot == PROT_NONE)
					continue;

				/**
				 * TODO: How to get the real offset of load
				 * maybe i can use /proc/PID/auxv to get it.
				 */
				if ((sibling->vm_pgoff << PAGE_SHIFT) == vaddr) {
					ldebug("Get %s voffset %lx\n",
						vma->name_, phdr->p_vaddr);
					sibling->voffset = phdr->p_vaddr;
				}
			}

			FALLTHROUGH;
		case PT_GNU_RELRO:
			gnu_relro_phdr = phdr;
			break;
		}
	}

	if (lowest_vaddr == ULONG_MAX) {
		lerror("%s: unable to find lowest load address(%lx).\n",
			vma->name_, lowest_vaddr);
		print_vma(stdout, true, vma, true);
		free(vma->vma_elf->phdrs);
		free(vma->vma_elf);
		vma->vma_elf = NULL;
		vma->is_elf = false;
		vma->is_share_lib = false;
		return -1;
	}

	vma->vma_elf->load_addr = vma->vm_start - lowest_vaddr;

	for (i = 0; i < vma->vma_elf->ehdr.e_phnum; i++) {
		GElf_Phdr *phdr = &vma->vma_elf->phdrs[i];
		struct vm_area_struct *sibling, *tmpvma;

		switch (phdr->p_type) {

		case PT_LOAD:
		case PT_GNU_RELRO:
			/* leader */
			match_vma_phdr(vma, phdr, vma->vma_elf->load_addr,
				       gnu_relro_phdr);
			/* siblings */
			list_for_each_entry_safe(sibling, tmpvma,
						 &vma->siblings, siblings) {
				match_vma_phdr(sibling, phdr,
					       vma->vma_elf->load_addr,
					       gnu_relro_phdr);
			}
			break;
		default:
			break;
		}
	}

	linfo("%s vma start %lx, load_addr %lx\n",
		vma->name_, vma->vm_start, vma->vma_elf->load_addr);

	return 0;
}

void vma_free_elf(struct vm_area_struct *vma)
{
	if (!vma->is_elf || vma->type == VMA_ULPATCH)
		return;

	free(vma->vma_elf->phdrs);
	free(vma->vma_elf);
}

static unsigned long offset_to_vaddr(struct vm_area_struct *vma, loff_t offset)
{
	return vma->vm_start + offset - ((loff_t)vma->vm_pgoff << PAGE_SHIFT);
}

/**
 * This function use to calculate the real symbol value, because load_addr's
 * effect.
 */
unsigned long task_vma_symbol_vaddr(const struct symbol *sym)
{
	unsigned long addr = 0;
	struct vm_area_struct *vma_leader = sym->vma;
	struct task_struct *task = vma_leader->task;
	unsigned long off = sym->sym.st_value;

	if (vma_leader != vma_leader->leader) {
		lerror("Symbol vma must be leader.\n");
		return 0;
	}

	if (vma_leader->is_share_lib) {
		struct vm_area_struct *vma, *tmpvma;

		list_for_each_entry_safe(vma, tmpvma, &vma_leader->siblings,
					 siblings) {

			/* Ignore vma holes, ---p */
			if (vma->prot == PROT_NONE)
				continue;

			if (off < (vma->vm_pgoff << PAGE_SHIFT))
				break;
		}

		/* FIXME: Maybe replace voffset here like VMA_SELF */
		addr = vma->vm_start + (off - vma->voffset);

	} else if (vma_leader->type == VMA_SELF) {
		/**
		 * If PIE, we should call offset_to_vaddr(), if no-PIE, use
		 * the offset directly.
		 */
		addr = task->is_pie ?
			offset_to_vaddr(sym->vma, off) :
			vma_leader->vma_elf->load_addr + off;
	} else
		addr = off;

	ldebug("Get symbol %s addr %lx\n", sym->name, addr);
	return addr;
}

struct symbol *task_vma_find_symbol(struct task_struct *task, const char *name,
				    int type)
{
	struct rb_node *node;
	struct symbol tmp = {
		.name = (char *)name,
		.type = type,
		.sym_type = SYM_TYPE_DEFINED,
	};

	ldebug("try find symbol %s\n", name);

	node = rb_search_node(&task->vma_symbols, cmp_symbol_name,
			      (unsigned long)&tmp);
	return node ? rb_entry(node, struct symbol, node) : NULL;
}

int task_vma_link_symbol(struct symbol *s, struct vm_area_struct *leader)
{
	struct rb_node *node;
	struct task_struct *task;
	struct vm_area_struct *vma;
	unsigned long vaddr;

	task = leader->task;
	vaddr = leader->vma_elf->load_addr + s->sym.st_value;

	vma = leader;

	ldebug("symbol: st_value %s:%lx(%lx) in vma %s:%lx\n",
	       s->name, s->sym.st_value, vaddr,
	       vma->name_, vma->vm_start);

	if (get_log_level() >= LOG_DEBUG)
		fprint_sym(get_log_fp(), &s->sym, s->name, NULL, true);

	s->vma = vma;
	s->type = GELF_ST_TYPE(s->sym.st_info);

	/**
	 * TODO: Get the symbol belongs to which phdrs.
	 */

	node = rb_insert_node(&task->vma_symbols, &s->node, cmp_symbol_name,
			      (unsigned long)s);
	if (unlikely(node))
		lwarning("%s: symbol %s already exist\n", task->comm, s->name);
	else
		ldebug("%s: add symbol %s addr %lx success.\n", task->comm,
			s->name, s->sym.st_value);
	return node ? -EINVAL : 0;
}

int task_vma_alloc_link_symbol(struct vm_area_struct *leader, const char *name,
			       GElf_Sym *sym)
{
	int err = 0;
	struct symbol *new;

	/* skip undefined symbols */
	if (is_undef_symbol(sym)) {
		ldebug("%s undef symbol: %s %lx\n", basename(leader->name_),
			name, sym->st_value);
		/* Skip undefined symbol */
		if (get_log_level() >= LOG_DEBUG)
			fprint_sym(get_log_fp(), sym, name, NULL, true);
		return 0;
	}

	/* allocate a symbol, and add it to task struct */
	new = alloc_symbol(name, sym);
	if (!new) {
		lerror("Alloc symbol failed, %s\n", name);
		return -ENOMEM;
	}

	ldebug("SELF %s %lx\n", new->name, new->sym.st_value);
	err = task_vma_link_symbol(new, leader);
	if (err)
		free_symbol(new);

	return err;
}

/**
 * load_self_vma_symbols - load self symbols from ELF file
 *
 * @vma - self vma
 */
static int load_self_vma_symbols(struct vm_area_struct *leader)
{
	int err = 0;
	struct task_struct *task = leader->task;
	struct symbol *sym, *tmp;
	struct rb_root *root = &task->exe_elf->symbols;

	rbtree_postorder_for_each_entry_safe(sym, tmp, root, node)
		err |= task_vma_alloc_link_symbol(leader, sym->name, &sym->sym);

	return err;
}

int vma_load_all_symbols(struct vm_area_struct *vma)
{
	int err = 0;
	size_t i;
	GElf_Dyn *dynamics = NULL;
	GElf_Phdr *dynamic_phdr = NULL;
	GElf_Sym *syms = NULL;
	char *buffer = NULL;
	struct task_struct *task;

	unsigned long symtab_addr, strtab_addr;
	unsigned long symtab_sz, strtab_sz;


	if (!vma->is_elf || !vma->vma_elf)
		return 0;

	task = vma->task;

	symtab_addr = strtab_addr = 0;
	symtab_sz = strtab_sz = 0;


	/* load all self symbols */
	if (vma->type == VMA_SELF)
		return load_self_vma_symbols(vma);

	/**
	 * Find PT_DYNAMIC program header
	 */
	for (i = 0; i < vma->vma_elf->ehdr.e_phnum; i++) {
		if (vma->vma_elf->phdrs[i].p_type == PT_DYNAMIC) {
			dynamic_phdr = &vma->vma_elf->phdrs[i];
			break;
		}
	}

	if (!dynamic_phdr) {
		lerror("No PT_DYNAMIC in %s\n", vma->name_);
		return -ENOENT;
	}

	dynamics = malloc(dynamic_phdr->p_memsz);
	if (!dynamics) {
		lerror("Malloc dynamics failed %s\n", vma->name_);
		return -ENOMEM;
	}

	err = memcpy_from_task(task, dynamics,
			       vma->vma_elf->load_addr + dynamic_phdr->p_vaddr,
			       dynamic_phdr->p_memsz);
	if (err == -1 || err < dynamic_phdr->p_memsz) {
		lerror("Task read mem failed, %lx.\n",
			vma->vm_start + dynamic_phdr->p_vaddr);
		goto out_free;
	}

	/* For each Dynamic */
	for (i = 0; i < dynamic_phdr->p_memsz / sizeof(GElf_Dyn); i++) {
		GElf_Dyn *curdyn = dynamics + i;

		switch (curdyn->d_tag) {
		case DT_SYMTAB:
			symtab_addr = curdyn->d_un.d_ptr;
			break;
		case DT_STRTAB:
			strtab_addr = curdyn->d_un.d_ptr;
			break;
		case DT_STRSZ:
			strtab_sz = curdyn->d_un.d_val;
			break;
		case DT_SYMENT:
			if (curdyn->d_un.d_val != sizeof(GElf_Sym)) {
				lerror("Dynsym entry size is %ld expected %ld\n",
					curdyn->d_un.d_val, sizeof(GElf_Sym));
				goto out_free;
			}
			break;
		default:
			break;
		}
	}

	symtab_sz = (strtab_addr - symtab_addr);

	if (strtab_sz == 0 || symtab_sz == 0) {
		memshowinlog(LOG_INFO, dynamics, dynamic_phdr->p_memsz);
		lwarning("No strtab, p_memsz %ld, p_vaddr %lx. "
			 "strtab(%lx) symtab(%lx) %s %lx\n",
			 dynamic_phdr->p_memsz, dynamic_phdr->p_vaddr,
			 strtab_addr, symtab_addr, vma->name_, vma->vm_start);
	}

	buffer = malloc(symtab_sz + strtab_sz);
	if (!buffer) {
		lerror("Malloc %ld bytes failed\n", symtab_sz + strtab_sz);
		goto out_free;
	}
	memset(buffer, 0x0, symtab_sz + strtab_sz);

	ldebug("%s: symtab_addr %lx, load_addr: %lx, vma start %lx\n",
		vma->name_,
		symtab_addr,
		vma->vma_elf->load_addr,
		vma->vm_start);

	/**
	 * [vdso] need add load_addr or vma start address.
	 *
	 * $ readelf -S vdso.so
	 * There are 16 section headers, starting at offset 0xe98:
	 * Section Headers:
	 *  [Nr] Name              Type             Address           Offset
	 *       Size              EntSize          Flags  Link  Info  Align
	 *  [ 3] .dynsym           DYNSYM           00000000000001c8  000001c8
	 *       0000000000000138  0000000000000018   A       4     1     8
	 */
	if (vma->type == VMA_VDSO)
		symtab_addr += vma->vma_elf->load_addr;

	err = memcpy_from_task(task, buffer, symtab_addr, strtab_sz + symtab_sz);
	if (err == -1 || err < strtab_sz + symtab_sz) {
		lerror("load symtab failed.\n");
		goto out_free_buffer;
	}

	ldebug("%s\n", vma->name_);
	memshowinlog(LOG_INFO, buffer, strtab_sz + symtab_sz);

	/* For each symbol */
	syms = (GElf_Sym *)buffer;

	for (i = 0; i < symtab_sz / sizeof(GElf_Sym); i++) {
		struct symbol *s;
		GElf_Sym *sym = syms + i;
		const char *symname = buffer + symtab_sz + syms[i].st_name;

		if (is_undef_symbol(sym) || strlen(symname) == 0)
			continue;

		ldebug("%s: %s\n", vma->name_, symname);

		/* allocate a symbol, and add it to task struct */
		s = alloc_symbol(symname, sym);
		if (!s) {
			lerror("Alloc symbol failed, %s\n", symname);
			continue;
		}

		err = task_vma_link_symbol(s, vma);
		if (err)
			free_symbol(s);
	}

out_free_buffer:
	free(buffer);
out_free:
	free(dynamics);
	return 0;
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
			lerror("sscanf failed.\n");
			return -1;
		}
#if 1
		if (update_ulp) {
			old = find_vma(task, start + 1);
			/* Skip if alread exist. */
			if (old && old->vm_start == start &&
			    old->vm_end == end) {
				lwarning("vma %s alread exist.\n", name_);
				continue;
			} else
				lwarning("insert vma %s.\n", name_);
		}
#endif

		vma = alloc_vma(task);

		vma->vm_start = start;
		vma->vm_end = end;
		memcpy(vma->perms, perms, sizeof(vma->perms));
		vma->prot = __perms2prot(perms);
		vma->vm_pgoff = (off >> PAGE_SHIFT);
		vma->major = major;
		vma->minor = minor;
		vma->inode = inode;
		strncpy(vma->name_, name_, sizeof(vma->name_));
		vma->type = get_vma_type(task->pid, task->exe, name_);

		/* Find libc.so */
		if (!task->libc_vma && vma->type == VMA_LIBC &&
		    vma->prot & PROT_EXEC) {
			ldebug("Get x libc: 0x%lx\n", vma->vm_start);
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

int update_task_vmas_ulp(struct task_struct *task)
{
	return read_task_vmas(task, true);
}

void print_task(FILE *fp, const struct task_struct *task, bool detail)
{
	if (!task || !fp)
		return;

	fprintf(fp, "Command: %-32s\n", task->comm);
	fprintf(fp, "Exe:     %-32s\n", task->exe);
	fprintf(fp, "Pid:     %-32d\n", task->pid);
	fprintf(fp, "PIE:     %-32s\n", task->is_pie ? "YES" : "NO");
	if (task->max_ulp_id)
		fprintf(fp, "Patched: YES (num %d)\n", task->max_ulp_id);

	if (!detail)
		return;

	/* Detail */
	fprintf(fp, "FTO:     %-32x\n", task->fto_flag);
	fprintf(fp, "MemFD:   %-32d\n", task->proc_mem_fd);
}

void print_vma(FILE *fp, bool first_line, struct vm_area_struct *vma, bool detail)
{
	int i;

	if (!vma) {
		lerror("Invalide pointer.\n");
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
		VMA_TYPE_NAME(vma->type),
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
				print_phdr(fp, pphdr, first);
				first = false;
			}
		}
		if (vma->is_matched_phdr)
			print_phdr(fp, &vma->phdr, true);
		/* Add more information here */
		if (fp == stdout || fp == stderr)
			fprintf(fp, "\033[0m");
	}
}

void print_thread(FILE *fp, struct task_struct *task, struct thread *thread)
{
	fprintf(fp, "pid %d, tid %d\n", task->pid, thread->tid);
}

void print_fd(FILE *fp, struct task_struct *task, struct fd *fd)
{
	fprintf(fp, "fd %d -> %s\n", fd->fd, fd->symlink);
}

int dump_task(const struct task_struct *task, bool detail)
{
	print_task(stdout, task, detail);
	return 0;
}

void dump_task_vmas(struct task_struct *task, bool detail)
{
	int first_line = 1;
	struct vm_area_struct *vma;

	list_for_each_entry(vma, &task->vma_list, node_list) {
		print_vma(stdout, first_line, vma, detail);
		first_line = 0;
	}

	printf("\n(E)ELF, (S)SharedLib, (P)MatchPhdr, (L)Leader\n");
}

int dump_task_addr_to_file(const char *ofile, struct task_struct *task,
			   unsigned long addr, unsigned long size)
{
	void *mem = NULL;

	/* default is stdout */
	int nbytes;

	/* If no output file name is specified, then the default output to stdout
	 * can be output using redirection. */
	int fd = fileno(stdout);

	if (ofile) {
		fd = open(ofile, O_CREAT | O_RDWR, 0664);
		if (fd <= 0) {
			lerror("open %s: %s\n", ofile, strerror(errno));
			return -1;
		}
	}
	struct vm_area_struct *vma = find_vma(task, addr);
	if (!vma) {
		lerror("vma not exist.\n");
		return -1;
	}

	mem = malloc(size);

	memcpy_from_task(task, mem, addr, size);

	/* write to file or stdout */
	nbytes = write(fd, mem, size);
	if (nbytes != size) {
		lerror("write failed, %s.\n", strerror(errno));
		free(mem);
		return -1;
	}

	free(mem);
	if (fd != fileno(stdout))
		close(fd);

	return 0;
}

int dump_task_vma_to_file(const char *ofile, struct task_struct *task,
			  unsigned long addr)
{
	size_t vma_size = 0;
	struct vm_area_struct *vma = find_vma(task, addr);
	if (!vma) {
		lerror("vma not exist.\n");
		return -1;
	}

	vma_size = vma->vm_end - vma->vm_start;

	return dump_task_addr_to_file(ofile, task, vma->vm_start, vma_size);
}

void dump_task_threads(struct task_struct *task, bool detail)
{
	struct thread *thread;

	if (!(task->fto_flag & FTO_THREADS)) {
		lerror("Not set FTO_THREADS(%ld) flag\n", FTO_THREADS);
		return;
	}

	list_for_each_entry(thread, &task->threads_list, node)
		print_thread(stdout, task, thread);
}

void dump_task_fds(struct task_struct *task, bool detail)
{
	struct fd *fd;

	if (!(task->fto_flag & FTO_FD)) {
		lerror("Not set FTO_FD(%ld) flag\n", FTO_FD);
		return;
	}

	list_for_each_entry(fd, &task->fds_list, node)
		print_fd(stdout, task, fd);
}

int free_task_vmas(struct task_struct *task)
{
	struct vm_area_struct *vma, *tmpvma;

	list_for_each_entry_safe(vma, tmpvma, &task->vma_list, node_list) {
		unlink_vma(task, vma);
		free_vma(vma);
	}

	list_init(&task->vma_list);
	list_init(&task->ulp_list);
	list_init(&task->threads_list);
	list_init(&task->fds_list);
	rb_init(&task->vmas_rb);

	task->libc_vma = NULL;
	task->stack = NULL;

	return 0;
}

bool proc_pid_exist(pid_t pid)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "/proc/%d", pid);
	return fexist(path);
}

char *get_proc_pid_exe(pid_t pid, char *buf, size_t bufsz)
{
	ssize_t ret = 0;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	ret = readlink(path, buf, bufsz);
	if (ret < 0) {
		lerror("readlink %s failed, %s\n", path, strerror(errno));
		return NULL;
	}
	return buf;
}

static int __get_comm(struct task_struct *task)
{
	char path[PATH_MAX];
	int ret;
	FILE *fp = NULL;

	ret = snprintf(path, sizeof(path), "/proc/%d/comm", task->pid);
	if (ret < 0) {
		lerror("readlink %s failed, %s\n", path, strerror(errno));
		return -errno;
	}

	fp = fopen(path, "r");

	ret = fscanf(fp, "%s", task->comm);
	if (ret == EOF) {
		lerror("fscanf(%s) %m\n", path);
		return -errno;
	}

	fclose(fp);

	return 0;
}

static int __get_exe(struct task_struct *task)
{
	char path[PATH_MAX], realpath[PATH_MAX];
	ssize_t ret;

	snprintf(path, sizeof(path), "/proc/%d/exe", task->pid);
	ret = readlink(path, realpath, sizeof(realpath));
	if (ret < 0) {
		lerror("readlink %s failed, %s\n", path, strerror(errno));
		return -errno;
	}
	realpath[ret] = '\0';

	if (!fexist(realpath)) {
		lerror("Execute %s is removed!\n", realpath);
		return -ENOENT;
	}

	task->exe = strdup(realpath);

	return 0;
}

int load_task_auxv(pid_t pid, struct task_struct_auxv *pauxv)
{
	int fd, n, ret = 0;
	char buf[PATH_MAX];
	GElf_auxv_t auxv;

	memset(pauxv, 0x00, sizeof(struct task_struct_auxv));
	snprintf(buf, PATH_MAX - 1, "/proc/%d/auxv", pid);
	fd = open(buf, O_RDONLY);
	if (fd == -1) {
		lerror("Open %s failed, %s\n", buf, strerror(errno));
		ret = -errno;
		goto close_exit;
	}

	while (true) {
		n = read(fd, &auxv, sizeof(auxv));
		if (n < sizeof(auxv))
			break;
		switch (auxv.a_type) {
		case AT_PHDR:
			pauxv->auxv_phdr = auxv.a_un.a_val;
			break;
		case AT_BASE:
			pauxv->auxv_interp = auxv.a_un.a_val;
			break;
		case AT_ENTRY:
			pauxv->auxv_entry = auxv.a_un.a_val;
			break;
		}
	}

	if (pauxv->auxv_phdr == 0) {
		lerror("Not found AT_PHDR in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}
	if (pauxv->auxv_interp == 0) {
		lerror("Not found AT_BASE in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}
	if (pauxv->auxv_entry == 0) {
		lerror("Not found AT_ENTRY in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}

close_exit:
	close(fd);
	return ret;
}

int print_task_auxv(FILE *fp, const struct task_struct *task)
{
	const struct task_struct_auxv *pauxv = &task->auxv;

	if (!fp)
		fp = stdout;

	fprintf(fp, "%-8s %-16s\n", "TYPE", "VALUE");
	fprintf(fp, "%-8s %-#16lx\n", "AT_PHDR", pauxv->auxv_phdr);
	fprintf(fp, "%-8s %-#16lx\n", "AT_BASE", pauxv->auxv_interp);
	fprintf(fp, "%-8s %-#16lx\n", "AT_ENTRY", pauxv->auxv_entry);

	return 0;
}

int load_task_status(pid_t pid, struct task_status *status)
{
	int fd, ret = 0;
	char buf[PATH_MAX];
	FILE *fp;
	struct task_status ts;

	memset(&ts, 0x00, sizeof(struct task_status));
	snprintf(buf, PATH_MAX - 1, "/proc/%d/status", pid);

	fd = open(buf, O_RDONLY);
	fp = fdopen(fd, "r");
	if (fd == -1 || !fd) {
		lerror("Open %s failed, %s\n", buf, strerror(errno));
		ret = -errno;
		goto close_exit;
	}

	ts.uid = ts.euid = ts.suid = ts.fsuid = -1;
	ts.gid = ts.egid = ts.sgid = ts.fsgid = -1;

	fseek(fp, 0, SEEK_SET);
	do {
		int r;
		char line[1024], label[128];

		if (!fgets(line, sizeof(line), fp))
			break;
		ldebug("Status: %s\n", line);

		if (!strncmp(line, "Uid:", 4)) {
			r = sscanf(line, "%s %d %d %d %d", label,
					&ts.uid,
					&ts.euid,
					&ts.suid,
					&ts.fsuid);
			if (r <= 0) {
				lerror("sscanf failed.\n");
				ret = -errno;
				goto close_exit;
			}
		}

		if (!strncmp(line, "Gid:", 4)) {
			r = sscanf(line, "%s %d %d %d %d", label,
					&ts.gid,
					&ts.egid,
					&ts.sgid,
					&ts.fsgid);
			if (r <= 0) {
				lerror("sscanf failed.\n");
				ret = -errno;
				goto close_exit;
			}
		}

		/* TODO: Parse more lines */

	} while (true);

	if (ts.uid == -1 || ts.euid == -1 || ts.suid == -1 || ts.fsuid == -1 ||
	    ts.gid == -1 || ts.egid == -1 || ts.sgid == -1 || ts.fsgid == -1) {
		lerror("Not found Uid: or Gid: in %s\n", buf);
		ret = -ENOENT;
		goto close_exit;
	}

	memcpy(status, &ts, sizeof(struct task_status));

close_exit:
	fclose(fp);
	close(fd);
	return ret;
}

int print_task_status(FILE *fp, const struct task_struct *task)
{
	const struct task_status *ps = &task->status;

	if (!fp)
		fp = stdout;

	fprintf(fp, "Uid:\t%d\t%d\t%d\t%d\n", ps->uid, ps->euid, ps->suid, ps->fsuid);
	fprintf(fp, "Gid:\t%d\t%d\t%d\t%d\n", ps->gid, ps->egid, ps->sgid, ps->fsgid);
	return 0;
}

/**
 * Open target task
 *
 * @pid process Identifier
 * @flags flag FTO_
 */
struct task_struct *open_task(pid_t pid, int flag)
{
	struct task_struct *task = NULL;
	int o_flags;

	if (!proc_pid_exist(pid)) {
		lerror("pid %d is not exist.\n", pid);
		errno = -ENOENT;
		return NULL;
	}

	task = malloc(sizeof(struct task_struct));
	if (!task) {
		lerror("malloc task failed, %m.\n");
		goto failed;
	}

	memset(task, 0x0, sizeof(struct task_struct));

	task->fto_flag = flag;
	task->pid = pid;

	list_init(&task->vma_list);
	list_init(&task->ulp_list);
	list_init(&task->threads_list);
	list_init(&task->fds_list);
	rb_init(&task->vmas_rb);

	if (load_task_auxv(pid, &task->auxv))
		goto free_task;

	if (load_task_status(pid, &task->status))
		goto free_task;

	__get_comm(task);

	if (__get_exe(task))
		goto free_task;

	/* Open target process memory */
	o_flags = flag & FTO_RDWR ? O_RDWR : O_RDONLY;
	task->proc_mem_fd = __open_pid_mem(pid, o_flags);
	if (task->proc_mem_fd <= 0)
		goto free_task;

	task->proc_mem_fd = task->proc_mem_fd;

	if (read_task_vmas(task, false))
		goto free_task;

	rb_init(&task->vma_symbols);

	if (!task->libc_vma || !task->stack) {
		lerror("No libc or stack founded.\n");
		goto free_task;
	}

	if (flag & FTO_VMA_ELF) {
		struct vm_area_struct *tmp_vma;
		task_for_each_vma(tmp_vma, task)
			vma_peek_phdr(tmp_vma);
	}

	if (flag & FTO_VMA_ELF_SYMBOLS) {
		struct vm_area_struct *tmp_vma;
		task_for_each_vma(tmp_vma, task)
			vma_load_all_symbols(tmp_vma);
	}

	if (flag & FTO_SELF_PLT) {
		task->objdump = objdump_elf_load(task->exe);
	}

	/* Create a directory under ULP_PROC_ROOT_DIR */
	if (flag & FTO_PROC) {
		FILE *fp;
		char buffer[PATH_MAX];

		/* ULP_PROC_ROOT_DIR/PID */
		snprintf(buffer, PATH_MAX - 1, ULP_PROC_ROOT_DIR "/%d",
			 task->pid);
		if (mkdirat(0, buffer, MODE_0777) != 0 && errno != EEXIST) {
			lerror("mkdirat(2) for %d:%s failed.\n", task->pid,
			       task->exe);
			goto free_task;
		}

		/* ULP_PROC_ROOT_DIR/PID/TASK_PROC_COMM */
		sprintf(buffer + strlen(buffer), "/" TASK_PROC_COMM);
		fp = fopen(buffer, "w");
		fprintf(fp, "%s", task->comm);
		fclose(fp);

		/* ULP_PROC_ROOT_DIR/PID/TASK_PROC_MAP_FILES */
		snprintf(buffer, PATH_MAX - 1,
			 ULP_PROC_ROOT_DIR "/%d/" TASK_PROC_MAP_FILES,
			 task->pid);
		if (mkdirat(0, buffer, MODE_0777) != 0 && errno != EEXIST) {
			lerror("mkdirat(2) for %d:%s failed.\n", task->pid,
			       task->exe);
			goto free_task;
		}
	}

	/* /proc/PID/task/xxx */
	if (flag & FTO_THREADS) {
		DIR *dir;
		struct dirent *entry;
		pid_t child;
		struct thread *thread;
		char proc_task_dir[] = {"/proc/1234567890abc/task"};
		sprintf(proc_task_dir, "/proc/%d/task/", task->pid);
		dir = opendir(proc_task_dir);
		if (!dir) {
			lerror("opendir %s failed.\n", proc_task_dir);
			goto free_task;
		}
		while ((entry = readdir(dir)) != NULL) {
			if (!strcmp(entry->d_name , ".") || !strcmp(entry->d_name, ".."))
				continue;
			ldebug("Thread %s\n", entry->d_name);
			child = atoi(entry->d_name);
			/**
			 * Maybe we should skip the thread tid == pid, however,
			 * if that, we must add an extra list of extra opendir
			 * while loop, thus, we add the pid == tid thread to
			 * task.threads_list.
			 *
			 * TODO: Should we need update threads_list by timingly
			 * read /proc/PID/task/, make sure new thread created
			 * during the ULPatch patching or unpatching? Maybe this
			 * is a longterm work, but not now.
			 */
			if (child == task->pid)
				ldebug("Thread %s (pid)\n", entry->d_name);
			thread = malloc(sizeof(struct thread));
			thread->tid = child;
			list_init(&thread->node);
			list_add(&thread->node, &task->threads_list);
		}
		closedir(dir);
	}

	/* /proc/PID/fd/xxx */
	if (flag & FTO_FD) {
		DIR *dir;
		struct dirent *entry;
		int ifd;
		int ret;
		struct fd *fd;
		char proc_fd[PATH_MAX] = {"/proc/1234567890abc/fd/"};
		sprintf(proc_fd, "/proc/%d/fd/", task->pid);
		dir = opendir(proc_fd);
		if (!dir) {
			lerror("opendir %s failed.\n", proc_fd);
			goto free_task;
		}
		while ((entry = readdir(dir)) != NULL) {
			if (!strcmp(entry->d_name , ".") || !strcmp(entry->d_name, ".."))
				continue;
			ldebug("FD %s\n", entry->d_name);
			ifd = atoi(entry->d_name);

			fd = malloc(sizeof(struct fd));
			memset(fd, 0x00, sizeof(struct fd));

			fd->fd = ifd;

			/* Read symbol link */
			sprintf(proc_fd, "/proc/%d/fd/%d", task->pid, ifd);
			ret = readlink(proc_fd, fd->symlink, PATH_MAX);
			if (ret < 0) {
				lwarning("readlink %s failed\n", proc_fd);
				strncpy(fd->symlink, "[UNKNOWN]", PATH_MAX);
			}

			list_init(&fd->node);
			list_add(&fd->node, &task->fds_list);
		}
		closedir(dir);
	}

	return task;

free_task:
	close_task(task);
failed:
	return NULL;
}

bool task_is_pie(struct task_struct *task)
{
	return task->is_pie;
}

static void __clean_task_proc(struct task_struct *task)
{
	char buffer[PATH_MAX];

	ldebug("Task %s is not patched, clean task's proc.\n", task->comm);

	/* ULP_PROC_ROOT_DIR/PID/TASK_PROC_COMM */
	snprintf(buffer, PATH_MAX - 1, ULP_PROC_ROOT_DIR "/%d/" TASK_PROC_COMM,
		 task->pid);
	if (unlink(buffer) != 0)
		lerror("unlink(%s) for %d:%s failed, %s.\n",
			buffer, task->pid, task->exe, strerror(errno));

	/* ULP_PROC_ROOT_DIR/PID/TASK_PROC_MAP_FILES */
	snprintf(buffer, PATH_MAX - 1,
		 ULP_PROC_ROOT_DIR "/%d/" TASK_PROC_MAP_FILES, task->pid);
	/**
	 * If process was patched, we should not remove the proc directory,
	 * and rmdir can't remove the directory has file in it.
	 */
	if (rmdir(buffer) != 0)
		lerror("rmdir(%s) for %d:%s failed, %s.\n", buffer, task->pid,
			task->exe, strerror(errno));

	/* ULP_PROC_ROOT_DIR/PID */
	snprintf(buffer, PATH_MAX - 1, ULP_PROC_ROOT_DIR "/%d", task->pid);
	if (rmdir(buffer) != 0)
		lerror("rmdir(%s) for %d:%s failed, %s.\n", buffer, task->pid,
			task->exe, strerror(errno));
}

static void __check_and_free_task_proc(struct task_struct *task)
{
	int ulp_cnt = 0;
	struct vm_area_struct *vma;

	/**
	 * If process was patched, we should not remove the proc directory.
	 */
	task_for_each_vma(vma, task)
		if (vma->type == VMA_ULPATCH)
			ulp_cnt++;

	if (ulp_cnt == 0)
		__clean_task_proc(task);
}

int close_task(struct task_struct *task)
{
	struct vm_area_struct *tmp_vma;

	if (!task) {
		lerror("Try free NULL task.\n");
		return -EINVAL;
	}

	if (task->proc_mem_fd > STDERR_FILENO)
		close(task->proc_mem_fd);

	if (task->fto_flag & FTO_VMA_ELF) {
		task_for_each_vma(tmp_vma, task)
			vma_free_elf(tmp_vma);
	}

	if (task->fto_flag & FTO_VMA_ELF_FILE)
		task_for_each_vma(tmp_vma, task)
			elf_file_close(tmp_vma->name_);

	if (task->fto_flag & FTO_PROC)
		__check_and_free_task_proc(task);

	if (task->fto_flag & FTO_THREADS) {
		struct thread *thread, *tmpthread;
		list_for_each_entry_safe(thread, tmpthread, &task->threads_list, node) {
			free(thread);
		}
	}

	if (task->fto_flag & FTO_FD) {
		struct fd *fd, *tmpfd;
		list_for_each_entry_safe(fd, tmpfd, &task->fds_list, node) {
			free(fd);
		}
	}

	/* Destroy symbols rb tree */
	rb_destroy(&task->vma_symbols, rb_free_symbol);

	free_task_vmas(task);
	free(task->exe);
	free(task);
	return 0;
}

int task_attach(pid_t pid)
{
	int ret;
	int status;

	ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (ret != 0) {
		lerror("Attach %d failed. %s\n", pid, strerror(errno));
		return -errno;
	}
	do {
		ret = waitpid(pid, &status, __WALL);
		if (ret < 0) {
			lerror("can't wait for pid %d\n", pid);
			return -errno;
		}
		ret = 0;

		/* We are expecting SIGSTOP */
		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
			break;

		/* If we got SIGTRAP because we just got out of execve, wait
		 * for the SIGSTOP
		 */
		if (WIFSTOPPED(status))
			status = (WSTOPSIG(status) == SIGTRAP) ? 0 : WSTOPSIG(status);
		else if (WIFSIGNALED(status))
			/* Resend signal */
			status = WTERMSIG(status);

		ret = ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)status);
		if (ret < 0) {
			lerror("can't cont tracee\n");
			return -errno;
		}
	} while (1);

	return ret;
}

int task_detach(pid_t pid)
{
	long rv;
	rv = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (rv != 0) {
		lerror("Detach %d failed. %s\n", pid, strerror(errno));
		return -errno;
	}

	return rv;
}

static __unused int pid_write(int pid, void *dest, const void *src, size_t len)
{
	int ret = -1;
	unsigned char *s = (unsigned char *) src;
	unsigned char *d = (unsigned char *) dest;

	while (ROUND_DOWN(len, sizeof(unsigned long))) {
		if (ptrace(PTRACE_POKEDATA, pid, d, *(long *)s) == -1) {
			ret = -errno;
			goto err;
		}
		s += sizeof(unsigned long);
		d += sizeof(unsigned long);
		len -= sizeof(unsigned long);
	}

	if (len) {
		unsigned long tmp;
		tmp = ptrace(PTRACE_PEEKTEXT, pid, d, NULL);
		if (tmp == (unsigned long)-1 && errno)
			return -errno;
		memcpy(&tmp, s, len);

		ret = ptrace(PTRACE_POKEDATA, pid, d, tmp);
	}

	return 0;
err:
	return ret;
}

static __unused int pid_read(int pid, void *dst, const void *src, size_t len)
{
	int sz = len / sizeof(void *);
	unsigned char *s = (unsigned char *)src;
	unsigned char *d = (unsigned char *)dst;
	long word;

	while (sz-- != 0) {
		word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
		if (word == -1 && errno) {
			return -errno;
		}

		*(long *)d = word;
		s += sizeof(long);
		d += sizeof(long);
	}

	return len;
}

int memcpy_from_task(struct task_struct *task, void *dst, unsigned long task_src,
		     ssize_t size)
{
	int ret = -1;
	ret = pread(task->proc_mem_fd, dst, size, task_src);
	if (ret == -1) {
		lerror("pread(%d, %p, %ld, 0x%lx) = %d failed, %m\n",
			task->proc_mem_fd, dst, size, task_src, ret);
		do_backtrace(stdout);
	}
	/* pread(2) will return -1 if failed, keep it that way. */
	return ret;
}

int memcpy_to_task(struct task_struct *task, unsigned long task_dst, void *src,
		   ssize_t size)
{
	int ret = -1;
	ret = pwrite(task->proc_mem_fd, src, size, task_dst);
	if (ret == -1) {
		lerror("pwrite(%d, %p, %ld, 0x%lx)=%d failed, %s\n",
			task->proc_mem_fd, src, size, task_dst, ret, strerror(errno));
		do_backtrace(stdout);
	}
	/* pwrite(2) will return -1 if failed, keep it that way. */
	return ret;
}

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wuninitialized"
#pragma clang diagnostic ignored "-Wmaybe-uninitialized"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
static void
copy_regs(struct user_regs_struct *dst, struct user_regs_struct *src)
{
#define COPY_REG(x) dst->x = src->x
#if defined(__x86_64__)
	COPY_REG(r15);
	COPY_REG(r14);
	COPY_REG(r13);
	COPY_REG(r12);
	COPY_REG(rbp);
	COPY_REG(rbx);
	COPY_REG(r11);
	COPY_REG(r10);
	COPY_REG(r9);
	COPY_REG(r8);
	COPY_REG(rax);
	COPY_REG(rcx);
	COPY_REG(rdx);
	COPY_REG(rsi);
	COPY_REG(rdi);
#elif defined(__aarch64__)
	COPY_REG(regs[0]);
	COPY_REG(regs[1]);
	COPY_REG(regs[2]);
	COPY_REG(regs[3]);
	COPY_REG(regs[4]);
	COPY_REG(regs[5]);
	COPY_REG(regs[8]);
	COPY_REG(regs[29]);
	COPY_REG(regs[9]);
	COPY_REG(regs[10]);
	COPY_REG(regs[11]);
	COPY_REG(regs[12]);
	COPY_REG(regs[13]);
	COPY_REG(regs[14]);
	COPY_REG(regs[15]);
	COPY_REG(regs[16]);
	COPY_REG(regs[17]);
	COPY_REG(regs[18]);
	COPY_REG(regs[19]);
	COPY_REG(regs[20]);
#else
# error "Unsupport architecture"
#endif
#undef COPY_REG
}
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

int wait_for_stop(struct task_struct *task)
{
	int ret, status = 0;
	pid_t pid = task->pid;

	while (1) {
		ret = ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)status);
		if (ret < 0) {
			print_vma(stderr, true, task->libc_vma, false);
			lerror("ptrace(PTRACE_CONT, %d, ...) %s\n",
				pid, strerror(ESRCH));
			return -1;
		}

		ret = waitpid(pid, &status, __WALL);
		if (ret < 0) {
			lerror("can't wait tracee %d\n", pid);
			return -1;
		}
		if (WIFSTOPPED(status))  {
			if (WSTOPSIG(status) == SIGSTOP ||
				WSTOPSIG(status) == SIGTRAP) {
				break;
			}
			if (WSTOPSIG(status) == SIGSEGV) {
				lerror("Child process %d segment fault.\n", pid);
				return -1;
			}
			status = WSTOPSIG(status);
			continue;
		}

		status = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
	}
	return 0;
}

int task_syscall(struct task_struct *task, int nr, unsigned long arg1,
		 unsigned long arg2, unsigned long arg3, unsigned long arg4,
		 unsigned long arg5, unsigned long arg6, unsigned long *res)
{
	int ret;
	struct user_regs_struct old_regs, regs, syscall_regs;
	unsigned char __syscall[] = {SYSCALL_INSTR};
	unsigned char orig_code[sizeof(__syscall)];
	unsigned long libc_base = task->libc_vma->vm_start;

#if defined(__aarch64__)
	struct iovec orig_regs_iov, regs_iov;

	orig_regs_iov.iov_base = &old_regs;
	orig_regs_iov.iov_len = sizeof(old_regs);
	regs_iov.iov_base = &regs;
	regs_iov.iov_len = sizeof(regs);
#endif

	SYSCALL_REGS_PREPARE(syscall_regs, nr, arg1, arg2, arg3, arg4, arg5, arg6);

	errno = 0;

#if defined(__x86_64__)
	ret = ptrace(PTRACE_GETREGS, task->pid, NULL, &old_regs);
#elif defined(__aarch64__)
	ret = ptrace(PTRACE_GETREGSET, task->pid, (void *)NT_PRSTATUS,
		     (void *)&orig_regs_iov);
#else
# error "Unsupport architecture"
#endif
	if (ret == -1) {
		lerror("ptrace(PTRACE_GETREGS, %d, ...) failed, %s\n",
			task->pid, strerror(errno));
		return -errno;
	}

	memcpy_from_task(task, orig_code, libc_base, sizeof(__syscall));

	memcpy_to_task(task, libc_base, __syscall, sizeof(__syscall));

	regs = old_regs;

	SYSCALL_IP(regs) = libc_base;

	copy_regs(&regs, &syscall_regs);

#if defined(__x86_64__)
	ret = ptrace(PTRACE_SETREGS, task->pid, NULL, &regs);
#elif defined(__aarch64__)
	ret = ptrace(PTRACE_SETREGSET, task->pid, (void*)NT_PRSTATUS,
			(void*)&regs_iov);
#else
# error "Unsupport architecture"
#endif
	if (ret == -1) {
		lerror("ptrace(PTRACE_SETREGS, %d, ...) failed, %s\n",
			task->pid, strerror(errno));
		ret = -errno;
		goto poke_back;
	}

	ret = wait_for_stop(task);
	if (ret < 0) {
		lerror("failed call to func\n");
		goto poke_back;
	}

#if defined(__x86_64__)
	ret = ptrace(PTRACE_GETREGS, task->pid, NULL, &regs);
#elif defined(__aarch64__)
	ret = ptrace(PTRACE_GETREGSET, task->pid, (void *)NT_PRSTATUS,
		     (void *)&regs_iov);
#else
# error "Unsupport architecture"
#endif
	if (ret == -1) {
		lerror("ptrace(PTRACE_GETREGS, %d, ...) failed, %s\n",
			task->pid, strerror(errno));
		ret = -errno;
		goto poke_back;
	}

#if defined(__x86_64__)
	ret = ptrace(PTRACE_SETREGS, task->pid, NULL, &old_regs);
#elif defined(__aarch64__)
	ret = ptrace(PTRACE_SETREGSET, task->pid, (void*)NT_PRSTATUS,
		     (void*)&orig_regs_iov);
#else
# error "Unsupport architecture"
#endif
	if (ret == -1) {
		lerror("ptrace(PTRACE_SETREGS, %d, ...) failed, %s\n",
			task->pid, strerror(errno));
		ret = -errno;
		goto poke_back;
	}

	syscall_regs = regs;
	*res = SYSCALL_RET(syscall_regs);

	ldebug("result %lx\n", *res);

poke_back:
	memcpy_to_task(task, libc_base, orig_code, sizeof(__syscall));
	return ret;
}

unsigned long task_mmap(struct task_struct *task, unsigned long addr,
			size_t length, int prot, int flags, int fd,
			off_t offset)
{
	int ret;
	unsigned long result;

	ret = task_syscall(task, __NR_mmap, addr, length, prot, flags, fd,
			   offset, &result);
	if (ret < 0)
		return 0;
	return result;
}

int task_munmap(struct task_struct *task, unsigned long addr, size_t size)
{
	int ret;
	unsigned long result;

	ret = task_syscall(task, __NR_munmap, addr, size, 0, 0, 0, 0, &result);
	if (ret < 0)
		return -1;
	return result;
}

int task_msync(struct task_struct *task, unsigned long addr, size_t length,
	       int flags)
{
	int ret;
	unsigned long result;

	ret = task_syscall(task, __NR_msync, addr, length, flags, 0, 0, 0,
			   &result);
	if (ret < 0)
		return -1;
	return result;
}

int task_msync_sync(struct task_struct *task, unsigned long addr, size_t length)
{
	return task_msync(task, addr, length, MS_SYNC);
}
int task_msync_async(struct task_struct *task, unsigned long addr,
		     size_t length)
{
	return task_msync(task, addr, length, MS_ASYNC);
}

unsigned long task_malloc(struct task_struct *task, size_t length)
{
	unsigned long remote_addr;
	remote_addr = task_mmap(task, 0UL, length, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (remote_addr == (unsigned long)MAP_FAILED) {
		lerror("Remote malloc failed, %ld\n", remote_addr);
		return 0UL;
	}
	return remote_addr;
}

int task_free(struct task_struct *task, unsigned long addr, size_t length)
{
	return task_munmap(task, addr, length);
}

int task_open(struct task_struct *task, char *pathname, int flags, mode_t mode)
{
	int __unused ret;
	unsigned long result;

	unsigned long name;
	ssize_t name_len = 0;


	name_len = strlen(pathname) + 1;
	name = task_malloc(task, name_len);
	memcpy_to_task(task, name, pathname, name_len);

#if defined(__x86_64__)
	ret = task_syscall(task, __NR_open, name, flags, mode, 0, 0, 0,
			   &result);
#elif defined(__aarch64__)
	ret = task_syscall(task, __NR_openat, AT_FDCWD, name, flags, mode, 0, 0,
			   &result);
#else
# error "Error arch"
#endif

	task_free(task, name, name_len);
	return result;
}

/* There are some file descriptors we should never close them. */
static bool __should_skip_remote_fd(int remote_fd)
{
	int fd = remote_fd;
	/* We should never close 0,1,2 fd of target process. */
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
		lwarning("Try to close remote 0,1,2 file descriptor.\n");
		return true;
	}
	return false;
}

int task_close(struct task_struct *task, int remote_fd)
{
	int ret;
	unsigned long result;
	if (__should_skip_remote_fd(remote_fd))
		return -EINVAL;
	ret = task_syscall(task, __NR_close, remote_fd, 0, 0, 0, 0, 0, &result);
	return result | ret;
}

int task_ftruncate(struct task_struct *task, int remote_fd, off_t length)
{
	int ret;
	unsigned long result;

	if (__should_skip_remote_fd(remote_fd))
		return -EINVAL;
	ret = task_syscall(task, __NR_ftruncate, remote_fd, length, 0, 0, 0, 0,
			   &result);
	if (ret < 0)
		return 0;
	return result;
}

int task_fstat(struct task_struct *task, int remote_fd, struct stat *statbuf)
{
	int ret, ret_fstat;
	unsigned long remote_statbuf;
	unsigned long result;

	/* Alloc stat struct from remote */
	remote_statbuf = task_malloc(task, sizeof(struct stat));

	/* Call fstat(2) */
	ret_fstat = task_syscall(task, __NR_fstat, remote_fd, remote_statbuf,
				 0, 0, 0, 0, &result);
	if (ret_fstat < 0)
		lerror("fstat failed, ret %d, %ld\n", ret_fstat, result);

	ret = memcpy_from_task(task, statbuf, remote_statbuf, sizeof(struct stat));
	if (ret == -1 || ret != sizeof(struct stat))
		lerror("failed copy struct stat.\n");

	task_free(task, remote_statbuf, sizeof(struct stat));

	return ret_fstat;
}

int task_prctl(struct task_struct *task, int option, unsigned long arg2,
	       unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	int ret;
	unsigned long result;

	ret = task_syscall(task, __NR_prctl, option, arg2, arg3, arg4, arg5, 0,
			   &result);
	if (ret < 0)
		return 0;
	return result;
}

