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

	ulp_debug("MatchPhdr: %lx-%lx vs %lx-%lx "PROT_FMT" ret=%d\n",
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
		ulp_error("malloc failed.\n");
		return -ENOMEM;
	}
	mem = malloc(elf_mem_len);
	if (!mem) {
		ulp_error("malloc failed.\n");
		return -ENOMEM;
	}

	vma->ulp = ulp;
	ulp->elf_mem = mem;
	ulp->vma = vma;
	ulp->str_build_id = NULL;

	/* Copy VMA from target task memory space */
	ret = memcpy_from_task(task, ulp->elf_mem, vma->vm_start, elf_mem_len);
	if (ret == -1 || ret < elf_mem_len) {
		ulp_error("Failed read from %lx:%s\n", vma->vm_start, vma->name_);
		free_ulp(vma);
		return -EAGAIN;
	}

	ulp_debug("Add %s to ulpatch list.\n", vma->name_);
	list_add(&ulp->node, &task->ulp_list);
	return 0;
}

void free_ulp(struct vm_area_struct *vma)
{
	struct vma_ulp *ulp = vma->ulp;

	if (!ulp)
		return;

	ulp_debug("Remove %s from ulpatch list.\n", vma->name_);

	list_del(&ulp->node);
	if (ulp->str_build_id)
		free(ulp->str_build_id);

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

	ulp_debug("Load ulpatch vma %s.\n", vma->name_);

	ret = memcpy_from_task(task, &ehdr, vma->vm_start, sizeof(ehdr));
	if (ret == -1 || ret < sizeof(ehdr)) {
		ulp_error("Failed read from %lx:%s\n", vma->vm_start, vma->name_);
		return -EAGAIN;
	}

	if (!ehdr_magic_ok(&ehdr)) {
		ulp_error("VMA %s(%lx) is considered as ULPATCH, but it isn't ELF.",
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
static int vma_peek_elf_hdrs(struct vm_area_struct *vma)
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
		ulp_debug("skip %s\n", vma_type_name(vma->type));
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
		ulp_debug("Skip peek vma %s\n", vma->name_);
		return 0;
	}

	ulp_debug("Try peek elf hdr from %s, addr %lx\n", vma->name_,
		  vma->vm_start);

	/**
	 * Read the ELF header from target task memory.
	 */
	ret = memcpy_from_task(task, &ehdr, vma->vm_start, sizeof(ehdr));
	if (ret < sizeof(ehdr)) {
		ulp_error("Failed read from %lx:%s\n", vma->vm_start, vma->name_);
		return -EAGAIN;
	}

	/* If it's not ELF, return success, skip the non-ELF VMAs */
	if (!ehdr_ok(&ehdr))
		return 0;

	vma->is_elf = true;

	ulp_debug("%lx %s is ELF\n", vma->vm_start, vma->name_);

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
			ulp_debug("%s is PIE.\n", vma->name_);
			task->is_pie = true;
		}  else {
			ulp_debug("%s is not PIE.\n", vma->name_);
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

	if (vma->vma_elf->ehdr.e_phnum == 0) {
		ulp_debug("%s has no phdr\n", vma->name_);
		vma->vma_elf->phdrs = NULL;
		goto peek_phdrs_done;
	}

	phaddr = vma->vm_start + vma->vma_elf->ehdr.e_phoff;
	phsz = vma->vma_elf->ehdr.e_phnum * sizeof(GElf_Phdr);

	/**
	 * If no program headers, just return. we don't need it, such as:
	 * /usr/lib64/ld-linux-x86-64.so.2 has '.ELF' magic, but it's no phdr.
	 */
	if (phsz == 0) {
		ulp_warning("%s: no phdr, e_phoff %lx, skip it.\n",
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
	ulp_debug("peek phdr from target addr %lx, len %d\n", phaddr, phsz);
	if (memcpy_from_task(task, vma->vma_elf->phdrs, phaddr, phsz) < phsz) {
		free(vma->vma_elf->phdrs);
		free(vma->vma_elf);
		ulp_error("Failed to read %s program header.\n", vma->name_);
		return -EAGAIN;
	}

peek_phdrs_done:

	/**
	 * If type of the ELF is not ET_DYN, this is definitely not a shared
	 * library.
	 *
	 * Actually, if the executable file is compiled with '-fPIE'(Position-
	 * Independent Executable file), it's ET_DYN too.
	 */
	if (vma->vma_elf->ehdr.e_type != ET_DYN || vma->type == VMA_SELF) {
		is_share_lib = false;
		goto set_share_lib;
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
			goto set_share_lib;
		}
	}

set_share_lib:

	is_share_lib |= vma->type == VMA_LIBC;
	is_share_lib |= vma->type == VMA_LIB_UNKNOWN;

	vma->is_share_lib = !!is_share_lib;

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

			ulp_debug("PT_LOAD: %s, lowest_vaddr %lx\n", vma->name_,
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
					ulp_debug("Get %s voffset %lx\n",
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
		ulp_error("%s: unable to find lowest load address(%lx).\n",
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

	ulp_info("%s vma start %lx, load_addr %lx\n",
		vma->name_, vma->vm_start, vma->vma_elf->load_addr);

	return 0;
}

static int vma_load_elf_file(struct vm_area_struct *vma)
{
	struct task_struct *task = vma->task;

	if (!vma->is_elf)
		return -EINVAL;

	/**
	 * "[vdso]" vma is elf, but file is not exist, could not open it.
	 */
	if (task->fto_flag & FTO_VMA_ELF_FILE && fexist(vma->name_)) {
		vma->bfd_elf_file = bfd_elf_open(vma->name_);
		if (!vma->bfd_elf_file) {
			ulp_error("Open ELF bfd %s failed.\n", vma->name_);
			return -EINVAL;
		}
		switch (vma->type) {
		case VMA_SELF:
			task->exe_bfd = vma->bfd_elf_file;
			break;
		case VMA_LIBC:
			task->libc_bfd = vma->bfd_elf_file;
			break;
		default:
			break;
		}
	}

	return 0;
}

void vma_free_elf(struct vm_area_struct *vma)
{
	if (!vma->is_elf || vma->type == VMA_ULPATCH)
		return;

	free(vma->vma_elf->phdrs);
	free(vma->vma_elf);
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
			ulp_error("open %s: %s\n", ofile, strerror(errno));
			return -1;
		}
	}
	struct vm_area_struct *vma = find_vma(task, addr);
	if (!vma) {
		ulp_error("vma not exist.\n");
		return -1;
	}

	mem = malloc(size);

	memcpy_from_task(task, mem, addr, size);

	/* write to file or stdout */
	nbytes = write(fd, mem, size);
	if (nbytes != size) {
		ulp_error("write failed, %s.\n", strerror(errno));
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
		ulp_error("vma not exist.\n");
		return -1;
	}

	vma_size = vma->vm_end - vma->vm_start;

	return dump_task_addr_to_file(ofile, task, vma->vm_start, vma_size);
}

void dump_task_threads(struct task_struct *task, bool detail)
{
	struct thread *thread;

	if (!(task->fto_flag & FTO_THREADS)) {
		ulp_error("Not set FTO_THREADS(%ld) flag\n", FTO_THREADS);
		return;
	}

	list_for_each_entry(thread, &task->threads_list, node)
		print_thread(stdout, task, thread);
}

void dump_task_fds(struct task_struct *task, bool detail)
{
	struct fd *fd;

	if (!(task->fto_flag & FTO_FD)) {
		ulp_error("Not set FTO_FD(%ld) flag\n", FTO_FD);
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
		ulp_error("readlink %s failed, %s\n", path, strerror(errno));
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
		ulp_error("readlink %s failed, %s\n", path, strerror(errno));
		return -errno;
	}

	fp = fopen(path, "r");

	ret = fscanf(fp, "%s", task->comm);
	if (ret == EOF) {
		ulp_error("fscanf(%s) %m\n", path);
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
		ulp_error("readlink %s failed, %s\n", path, strerror(errno));
		return -errno;
	}
	realpath[ret] = '\0';

	if (!fexist(realpath)) {
		ulp_error("Execute %s is removed!\n", realpath);
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
		ulp_error("Open %s failed, %s\n", buf, strerror(errno));
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
		case AT_PHENT:
			pauxv->auxv_phent = auxv.a_un.a_val;
			break;
		case AT_PHNUM:
			pauxv->auxv_phnum = auxv.a_un.a_val;
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
		ulp_error("Not found AT_PHDR in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}
	if (pauxv->auxv_phent == 0) {
		ulp_error("Not found AT_PHENT in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}
	if (pauxv->auxv_phnum == 0) {
		ulp_error("Not found AT_PHNUM in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}
	if (pauxv->auxv_interp == 0) {
		ulp_error("Not found AT_BASE in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}
	if (pauxv->auxv_entry == 0) {
		ulp_error("Not found AT_ENTRY in %s\n", buf);
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
	fprintf(fp, "%-8s %ld (%-#lx)\n", "AT_PHENT", pauxv->auxv_phent,
							pauxv->auxv_phent);
	fprintf(fp, "%-8s %ld (%-#lx)\n", "AT_PHNUM", pauxv->auxv_phnum,
							pauxv->auxv_phnum);
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
		ulp_error("Open %s failed, %s\n", buf, strerror(errno));
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
		ulp_debug("Status: %s\n", line);

		if (!strncmp(line, "Uid:", 4)) {
			r = sscanf(line, "%s %d %d %d %d", label,
					&ts.uid,
					&ts.euid,
					&ts.suid,
					&ts.fsuid);
			if (r <= 0) {
				ulp_error("sscanf failed.\n");
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
				ulp_error("sscanf failed.\n");
				ret = -errno;
				goto close_exit;
			}
		}

		/* TODO: Parse more lines */

	} while (true);

	if (ts.uid == -1 || ts.euid == -1 || ts.suid == -1 || ts.fsuid == -1 ||
	    ts.gid == -1 || ts.egid == -1 || ts.sgid == -1 || ts.fsgid == -1) {
		ulp_error("Not found Uid: or Gid: in %s\n", buf);
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
	struct vm_area_struct *tmp_vma;

	if (!proc_pid_exist(pid)) {
		ulp_error("pid %d is not exist.\n", pid);
		errno = -ENOENT;
		return NULL;
	}

	task = malloc(sizeof(struct task_struct));
	if (!task) {
		ulp_error("malloc task failed, %m.\n");
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
	task_syms_init(&task->tsyms);

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

	if (!task->libc_vma || !task->stack) {
		ulp_error("No libc or stack founded.\n");
		goto free_task;
	}

	if (flag & FTO_VMA_ELF) {
		task_for_each_vma(tmp_vma, task) {
			vma_peek_elf_hdrs(tmp_vma);
			if (tmp_vma->is_elf)
				vma_load_elf_file(tmp_vma);
		}
	}

	if (flag & FTO_VMA_ELF_SYMBOLS) {
		task_for_each_vma(tmp_vma, task) {
			if (tmp_vma->is_elf)
				task_load_vma_elf_syms(tmp_vma);
		}
	}

	/* Create a directory under ULP_PROC_ROOT_DIR */
	if (flag & FTO_PROC) {
		FILE *fp;
		char buffer[PATH_MAX];

		/* ULP_PROC_ROOT_DIR/PID */
		snprintf(buffer, PATH_MAX - 1, ULP_PROC_ROOT_DIR "/%d",
			 task->pid);
		if (mkdirat(0, buffer, MODE_0777) != 0 && errno != EEXIST) {
			ulp_error("mkdirat(2) for %d:%s failed.\n", task->pid,
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
			ulp_error("mkdirat(2) for %d:%s failed.\n", task->pid,
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
			ulp_error("opendir %s failed.\n", proc_task_dir);
			goto free_task;
		}
		while ((entry = readdir(dir)) != NULL) {
			if (!strcmp(entry->d_name , ".") || !strcmp(entry->d_name, ".."))
				continue;
			ulp_debug("Thread %s\n", entry->d_name);
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
				ulp_debug("Thread %s (pid)\n", entry->d_name);
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
			ulp_error("opendir %s failed.\n", proc_fd);
			goto free_task;
		}
		while ((entry = readdir(dir)) != NULL) {
			if (!strcmp(entry->d_name , ".") || !strcmp(entry->d_name, ".."))
				continue;
			ulp_debug("FD %s\n", entry->d_name);
			ifd = atoi(entry->d_name);

			fd = malloc(sizeof(struct fd));
			memset(fd, 0x00, sizeof(struct fd));

			fd->fd = ifd;

			/* Read symbol link */
			sprintf(proc_fd, "/proc/%d/fd/%d", task->pid, ifd);
			ret = readlink(proc_fd, fd->symlink, PATH_MAX);
			if (ret < 0) {
				ulp_warning("readlink %s failed\n", proc_fd);
				strncpy(fd->symlink, "[UNKNOWN]", PATH_MAX);
			}

			list_init(&fd->node);
			list_add(&fd->node, &task->fds_list);
		}
		closedir(dir);
	}

	set_current_task(task);

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

	ulp_debug("Task %s is not patched, clean task's proc.\n", task->comm);

	/* ULP_PROC_ROOT_DIR/PID/TASK_PROC_COMM */
	snprintf(buffer, PATH_MAX - 1, ULP_PROC_ROOT_DIR "/%d/" TASK_PROC_COMM,
		 task->pid);
	if (unlink(buffer) != 0)
		ulp_error("unlink(%s) for %d:%s failed, %s.\n",
			buffer, task->pid, task->exe, strerror(errno));

	/* ULP_PROC_ROOT_DIR/PID/TASK_PROC_MAP_FILES */
	snprintf(buffer, PATH_MAX - 1,
		 ULP_PROC_ROOT_DIR "/%d/" TASK_PROC_MAP_FILES, task->pid);
	/**
	 * If process was patched, we should not remove the proc directory,
	 * and rmdir can't remove the directory has file in it.
	 */
	if (rmdir(buffer) != 0)
		ulp_error("rmdir(%s) for %d:%s failed, %s.\n", buffer, task->pid,
			task->exe, strerror(errno));

	/* ULP_PROC_ROOT_DIR/PID */
	snprintf(buffer, PATH_MAX - 1, ULP_PROC_ROOT_DIR "/%d", task->pid);
	if (rmdir(buffer) != 0)
		ulp_error("rmdir(%s) for %d:%s failed, %s.\n", buffer, task->pid,
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
		ulp_error("Try free NULL task.\n");
		return -EINVAL;
	}

	if (task->proc_mem_fd > STDERR_FILENO)
		close(task->proc_mem_fd);

	if (task->fto_flag & FTO_VMA_ELF) {
		task_for_each_vma(tmp_vma, task)
			vma_free_elf(tmp_vma);
	}

	if (task->fto_flag & FTO_VMA_ELF_FILE) {
		task_for_each_vma(tmp_vma, task) {
			if (tmp_vma->is_elf)
				bfd_elf_close(tmp_vma->bfd_elf_file);
		}
	}

	if (task->fto_flag & FTO_VMA_ELF_SYMBOLS)
		free_task_syms(task);

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

	free_task_vmas(task);
	free(task->exe);
	free(task);

	reset_current_task();

	return 0;
}

int task_attach(pid_t pid)
{
	int ret;
	int status;

	ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (ret != 0) {
		ulp_error("Attach %d failed. %s\n", pid, strerror(errno));
		return -errno;
	}
	do {
		ret = waitpid(pid, &status, __WALL);
		if (ret < 0) {
			ulp_error("can't wait for pid %d\n", pid);
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
			ulp_error("can't cont tracee\n");
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
		ulp_error("Detach %d failed. %s\n", pid, strerror(errno));
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

int memcpy_from_task(struct task_struct *task, void *dst,
		     unsigned long task_src, ssize_t size)
{
	int ret = -1;
	ret = pread(task->proc_mem_fd, dst, size, task_src);
	if (ret == -1) {
		ulp_error("pread(%d, %p, %ld, 0x%lx) = %d failed, %m\n",
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
		ulp_error("pwrite(%d, %p, %ld, 0x%lx)=%d failed, %m\n",
			task->proc_mem_fd, src, size, task_dst, ret);
		do_backtrace(stdout);
	}
	/* pwrite(2) will return -1 if failed, keep it that way. */
	return ret;
}

#define MAX_STR_LEN	1024

char *strcpy_from_task(struct task_struct *task, char *dst,
		       unsigned long task_src)
{
	int i;
	for (i = 0;; i++) {
		memcpy_from_task(task, &dst[i], task_src + i, 1);
		if (dst[i] == '\0' || i >= MAX_STR_LEN)
			break;
	}
	return dst;
}

char *strcpy_to_task(struct task_struct *task, unsigned long task_dst,
		     char *src)
{
	memcpy_to_task(task, task_dst, src, strlen(src) + 1);
	return src;
}
