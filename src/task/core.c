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

#include "elf/elf-api.h"

#include "utils/log.h"
#include "task/task.h"
#include "task/patch.h"

#if defined(__x86_64__)
#include "arch/x86_64/regs.h"
#include "arch/x86_64/instruments.h"
#elif defined(__aarch64__)
#include "arch/aarch64/regs.h"
#include "arch/aarch64/instruments.h"
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
		((phdr->p_flags & (PF_R | PF_W | PF_X)) ==
			vma_prot2flags(vma->prot));

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
	case VMA_VVAR_VCLOCK:
	case VMA_STACK:
	case VMA_UPROBES:
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
		ulp_error("Failed read from %lx:%s\n", vma->vm_start,
			  vma->name_);
		errno = EAGAIN;
		return -EAGAIN;
	}

	/* If it's not ELF, return success, skip the non-ELF VMAs */
	if (!ehdr_ok(&ehdr)) {
		errno = ENOENT;
		return 0;
	}

	vma->is_elf = true;

	ulp_debug("%lx %s is ELF\n", vma->vm_start, vma->name_);

	if (vma->type == VMA_SELF) {
		task->vma_root.self_elf = vma;
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

	if (!vma->is_elf) {
		errno = EINVAL;
		return -EINVAL;
	}

	/**
	 * "[vdso]" vma is elf, but file is not exist, could not open it.
	 */
	if (task->fto_flag & FTO_VMA_ELF_FILE && fexist(vma->name_)) {
		vma->bfd_elf_file = bfd_elf_open(vma->name_);
		if (!vma->bfd_elf_file) {
			ulp_error("Open ELF bfd %s failed.\n", vma->name_);
			errno = EINVAL;
			return -EINVAL;
		}
		switch (vma->type) {
		case VMA_SELF:
			task->vma_root.exe_bfd = vma->bfd_elf_file;
			break;
		case VMA_LIBC:
			task->vma_root.libc_bfd = vma->bfd_elf_file;
			break;
		default:
			break;
		}
	}

	return 0;
}

void vma_free_elf(struct vm_area_struct *vma)
{
	if (!vma->is_elf || vma->type == VMA_ULPATCH) {
		errno = EINVAL;
		return;
	}

	free(vma->vma_elf->phdrs);
	free(vma->vma_elf);
}

int print_task(FILE *fp, const struct task_struct *task, bool detail)
{
	if (!fp)
		fp = stdout;
	if (!task) {
		return -EINVAL;
	}

	fprintf(fp, "Command: %-32s\n", task->comm);
	fprintf(fp, "Exe:     %-32s\n", task->exe);
	fprintf(fp, "Pid:     %-32d\n", task->pid);
	fprintf(fp, "PIE:     %-32s\n", task->is_pie ? "YES" : "NO");
	if (task->ulp_root.max_id)
		fprintf(fp, "Patched: YES (num %d)\n", task->ulp_root.max_id);

	if (!detail)
		return 0;

	fprintf(fp, "FTO:     %-32x\n", task->fto_flag);
	fprintf(fp, "MemFD:   %-32d\n", task->proc_mem_fd);

	return 0;
}

void dump_task_vmas(FILE *fp, struct task_struct *task, bool detail)
{
	int first_line = 1;
	struct vm_area_struct *vma;

	if (!fp)
		fp = stdout;

	list_for_each_entry(vma, &task->vma_root.list, node_list) {
		print_vma(fp, first_line, vma, detail);
		first_line = 0;
	}

	fprintf(fp, "\n(E)ELF, (S)SharedLib, (P)MatchPhdr, (L)Leader\n");
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
			ulp_error("open %s: %m\n", ofile);
			return -1;
		}
	}
	struct vm_area_struct *vma = find_vma(task, addr);
	if (!vma) {
		ulp_error("%s vma not exist on 0x%lx.\n", task->comm, addr);
		return -1;
	}

	mem = malloc(size);

	memcpy_from_task(task, mem, addr, size);

	/* write to file or stdout */
	nbytes = write(fd, mem, size);
	if (nbytes != size) {
		ulp_error("write failed, %m.\n");
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
		ulp_error("%s vma not exist on 0x%lx.\n", task->comm, addr);
		return -1;
	}

	vma_size = vma->vm_end - vma->vm_start;

	return dump_task_addr_to_file(ofile, task, vma->vm_start, vma_size);
}

/**
 * Open target task
 *
 * @pid process Identifier
 * @flags flag FTO_
 */
struct task_struct *open_task(pid_t pid, int flag)
{
	int err = 0;
	struct task_struct *task = NULL;
	int o_flags;
	struct vm_area_struct *tmp_vma;

	if (!proc_pid_exist(pid)) {
		ulp_error("pid %d is not exist.\n", pid);
		errno = ENOENT;
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

	init_vma_root(&task->vma_root);
	init_vma_ulp_root(&task->ulp_root);
	init_thread_root(&task->thread_root);
	init_fds_root(&task->fds_root);
	task_syms_init(&task->tsyms);

	if (flag & FTO_AUXV) {
		err = load_task_auxv(pid, &task->auxv);
		if (err)
			goto free_task;
	}

	if (flag & FTO_STATUS) {
		err =proc_get_pid_status(pid, &task->status);
		if (err)
			goto free_task;
	}

	err = proc_pid_comm(task->pid, task->comm);
	if (err)
		goto free_task;

	if (!proc_pid_exe(task->pid, task->exe, sizeof(task->exe)))
		goto free_task;

	/* Open target process memory */
	o_flags = flag & FTO_RDWR ? O_RDWR : O_RDONLY;
	task->proc_mem_fd = open_pid_mem_flags(pid, o_flags);
	if (task->proc_mem_fd <= 0)
		goto free_task;

	task->proc_mem_fd = task->proc_mem_fd;

	err = read_task_vmas(task, false);
	if (err)
		goto free_task;

	if (!task->vma_root.libc_code || !task->vma_root.stack) {
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

	task_load_threads(task);
	task_load_fds(task);

	set_current_task(task);

	return task;

free_task:
	close_task(task);
failed:
	errno = -err;
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
	if (fexist(buffer) && unlink(buffer) != 0)
		ulp_error("unlink(%s) for %d:%s failed, %m.\n",
			buffer, task->pid, task->exe);

	/* ULP_PROC_ROOT_DIR/PID/TASK_PROC_MAP_FILES */
	snprintf(buffer, PATH_MAX - 1,
		 ULP_PROC_ROOT_DIR "/%d/" TASK_PROC_MAP_FILES, task->pid);
	/**
	 * If process was patched, we should not remove the proc directory,
	 * and rmdir can't remove the directory has file in it.
	 */
	if (fexist(buffer) && rmdir(buffer) != 0)
		ulp_error("rmdir(%s) for %d:%s failed, %m.\n", buffer,
			task->pid, task->exe);

	/* ULP_PROC_ROOT_DIR/PID */
	snprintf(buffer, PATH_MAX - 1, ULP_PROC_ROOT_DIR "/%d", task->pid);
	if (fexist(buffer) && rmdir(buffer) != 0)
		ulp_error("rmdir(%s) for %d:%s failed, %m.\n", buffer,
			task->pid, task->exe);
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
		struct thread_struct *thread, *tmpthread;
		list_for_each_entry_safe(thread, tmpthread,
			   &task->thread_root.list, node)
			free_thread(thread);
	}

	if (task->fto_flag & FTO_FD) {
		struct fd *fd, *tmpfd;
		list_for_each_entry_safe(fd, tmpfd, &task->fds_root.list, node)
			free_fd(fd);
	}

	free_task_vmas(task);
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
		ulp_error("Attach %d failed. %m, are you debugging pid=%d with"
			  " gdb or PTRACE_TRACEME\n", pid, pid);
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
		ulp_error("Detach %d failed. %m\n", pid);
		return -errno;
	}

	return rv;
}
