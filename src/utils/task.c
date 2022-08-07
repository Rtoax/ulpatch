// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <limits.h>
#include <stdlib.h>
#include <elf.h>

#include <elf/elf_api.h>

#include "log.h"
#include "task.h"

#if defined(__x86_64__)
#include "arch/x86_64/regs.h"
#elif defined(__aarch64__)
#include "arch/aarch64/regs.h"
#endif

LIST_HEAD(tasks_list);

int open_pid_maps(pid_t pid)
{
	int ret;
	char maps[] = "/proc/1234567890/maps";

	snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
	ret = open(maps, O_RDONLY);
	if (ret <= 0) {
		lerror("open %s failed. %s\n", maps, strerror(errno));
		ret = -errno;
	}
	return ret;
}

int open_pid_mem(pid_t pid)
{
	char mem[] = "/proc/1234567890/mem";
	snprintf(mem, sizeof(mem), "/proc/%d/mem", pid);
	int memfd = open(mem, O_RDWR);
	if (memfd <= 0) {
		lerror("open %s failed. %s\n", mem, strerror(errno));
	}
	return memfd;
}

struct vma_struct *alloc_vma()
{
	struct vma_struct *vma = malloc(sizeof(struct vma_struct));
	assert(vma && "alloc vma failed.");
	memset(vma, 0x00, sizeof(struct vma_struct));

	vma->type = VMA_NONE;

	list_init(&vma->node);

	return vma;
}

static inline int __vma_rb_cmp(struct rb_node *node, unsigned long key)
{
	struct vma_struct *vma = rb_entry(node, struct vma_struct, node_rb);
	struct vma_struct *new = (struct vma_struct *)key;

	if (new->end <= vma->start)
		return -1;
	else if (vma->start < new->end && vma->end > new->start)
		return 0;
	else if (vma->end <= new->start)
		return 1;

	assert(0 && "Try insert illegal vma.");
	return 0;
}

int insert_vma(struct task *task, struct vma_struct *vma)
{
	list_add(&vma->node, &task->vmas);
	rb_insert_node(&task->vmas_rb, &vma->node_rb,
		__vma_rb_cmp, (unsigned long)vma);
	return 0;
}

int unlink_vma(struct task *task, struct vma_struct *vma)
{
	list_del(&vma->node);
	rb_erase(&vma->node_rb, &task->vmas_rb);
	return 0;
}

int free_vma(struct vma_struct *vma)
{
	if (!vma)
		return -1;

	free(vma);
	return 0;
}

static inline int __find_vma_cmp(struct rb_node *node, unsigned long vaddr)
{
	struct vma_struct *vma = rb_entry(node, struct vma_struct, node_rb);

	if (vma->start > vaddr)
		return -1;
	else if (vma->start <= vaddr && vma->end > vaddr)
		return 0;
	else
		return 1;
}

struct vma_struct *find_vma(struct task *task, unsigned long vaddr)
{
	struct rb_node * rnode =
		rb_search_node(&task->vmas_rb, __find_vma_cmp, vaddr);
	if (rnode) {
		return rb_entry(rnode, struct vma_struct, node_rb);
	}
	return NULL;
}

struct vma_struct *next_vma(struct task *task, struct vma_struct *prev)
{
	struct rb_node *next;

	next = prev?rb_next(&prev->node_rb):rb_first(&task->vmas_rb);

	return  next?rb_entry(next, struct vma_struct, node_rb):NULL;
}

unsigned long find_vma_span_area(struct task *task, size_t size)
{
	struct vma_struct *ivma;
	struct rb_node * rnode;

	for (rnode = rb_first(&task->vmas_rb); rnode; rnode = rb_next(rnode)) {
		ivma = rb_entry(rnode, struct vma_struct, node_rb);
		struct rb_node *next_node = rb_next(rnode);
		struct vma_struct *next_vma;
		if (!next_node) {
			return 0;
		}
		next_vma = rb_entry(next_node, struct vma_struct, node_rb);
		if (next_vma->start - ivma->end >= size) {
			return ivma->end;
		}
	}
	lerror("No space fatal in target process, pid %d\n", task->pid);
	return 0;
}

static unsigned int __perms2prot(char *perms)
{
	unsigned int prot = 0;

	if (perms[0] == 'r')
		prot |= PROT_READ;
	if (perms[1] == 'w')
		prot |= PROT_WRITE;
	if (perms[2] == 'x')
		prot |= PROT_EXEC;
	/* Ignore 'p'/'s' flag, we don't need it */
	return prot;
}

static int free_task_vmas(struct task *task);

static int read_task_vmas(struct task *task, bool update)
{
	struct vma_struct *vma;
	int mapsfd;
	FILE *mapsfp;

	if (update) free_task_vmas(task);

	// open(2) /proc/PID/maps
	mapsfd = open_pid_maps(task->pid);
	if (mapsfd <= 0) {
		return -1;
	}
	lseek(mapsfd, 0, SEEK_SET);

	mapsfp = fdopen(mapsfd, "r");
	fseek(mapsfp, 0, SEEK_SET);
	do {
		unsigned long start, end, offset;
		unsigned int maj, min, inode;
		char perms[5], name_[256];
		int r;
		char line[1024];

		if (!fgets(line, sizeof(line), mapsfp))
			break;

		r = sscanf(line, "%lx-%lx %s %lx %x:%x %d %255s",
				&start, &end, perms, &offset,
				&maj, &min, &inode, name_);
		if (r <= 0) {
			lerror("sscanf failed.\n");
			return -1;
		}

		vma = alloc_vma();

		vma->start = start;
		vma->end = end;
		memcpy(vma->perms, perms, sizeof(vma->perms));
		vma->prot = __perms2prot(perms);
		vma->offset = offset;
		vma->maj = maj;
		vma->min = min;
		vma->inode = inode;
		strncpy(vma->name_, name_, sizeof(vma->name_));
		vma->type = get_vma_type(task->exe, name_);

		// Find libc.so
		if (!task->libc_vma
			&& vma->type == VMA_LIBC
			&& vma->prot & PROT_EXEC) {
			ldebug("Get libc:\n");
			task->libc_vma = vma;
		}

		// Find [stack]
		if (!task->stack && vma->type == VMA_STACK) {
			task->stack = vma;
		}

		insert_vma(task, vma);
	} while (1);

	fclose(mapsfp);
	close(mapsfd);

	return 0;
}

int update_task_vmas(struct task *task)
{
	return read_task_vmas(task, true);
}

void print_vma(struct vma_struct *vma)
{
	if (!vma) {
		lerror("Invalide pointer.\n");
		return;
	}
	printf("%10s: %016lx-%016lx %6s %8lx %4x:%4x %8d %s\n",
			VMA_TYPE_NAME(vma->type),
			vma->start, vma->end, vma->perms, vma->offset,
			vma->maj, vma->min, vma->inode, vma->name_);
}

int dump_task(const struct task *task)
{
	printf(
		"COMM: %s\n"
		"PID:  %d\n"
		"EXE:  %s\n",
		task->comm,
		task->pid,
		task->exe
	);

	return 0;
}

void dump_task_vmas(struct task *task)
{
	struct vma_struct *vma;

	list_for_each_entry(vma, &task->vmas, node) {
		print_vma(vma);
	}
}

static int free_task_vmas(struct task *task)
{
	struct vma_struct *vma, *tmpvma;

	list_for_each_entry_safe(vma, tmpvma, &task->vmas, node) {
		unlink_vma(task, vma);
		free_vma(vma);
	}

	list_init(&task->vmas);
	rb_init(&task->vmas_rb);

	task->libc_vma = NULL;
	task->stack = NULL;

	return 0;
}

bool proc_pid_exist(pid_t pid)
{
	char path[128];

	snprintf(path, sizeof(path), "/proc/%d", pid);
	return fexist(path);
}

char *get_proc_pid_exe(pid_t pid, char *buf, size_t bufsz)
{
	ssize_t ret = 0;
	char path[128];

	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	ret = readlink(path, buf, bufsz);
	if (ret < 0) {
		lerror("readlink %s failed, %s\n", path, strerror(errno));
		return NULL;
	}
	return buf;
}

static int __get_comm(struct task *task)
{
	char path[128];
	ssize_t ret;
	FILE *fp = NULL;

	ret = snprintf(path, sizeof(path), "/proc/%d/comm", task->pid);
	if (ret < 0) {
		lerror("readlink %s failed, %s\n", path, strerror(errno));
		return -errno;
	}

	fp = fopen(path, "r");

	fscanf(fp, "%s", task->comm);

	fclose(fp);

	return 0;
}

static int __get_exe(struct task *task)
{
	char path[128], realpath[128];
	ssize_t ret;

	snprintf(path, sizeof(path), "/proc/%d/exe", task->pid);
	ret = readlink(path, realpath, sizeof(realpath));
	if (ret < 0) {
		lerror("readlink %s failed, %s\n", path, strerror(errno));
		return -errno;
	}
	realpath[ret] = '\0';
	task->exe = strdup(realpath);

	return 0;
}

struct task *open_task(pid_t pid, enum fto_flag flag)
{
	struct task *task = NULL;
	int memfd;

	memfd = open_pid_mem(pid);
	if (memfd <= 0) {
		return NULL;
	}


	task = malloc(sizeof(struct task));
	assert(task && "malloc failed");
	memset(task, 0x0, sizeof(struct task));

	list_init(&task->vmas);
	rb_init(&task->vmas_rb);

	task->fto_flag = flag;
	task->pid = pid;
	__get_comm(task);
	__get_exe(task);
	task->proc_mem_fd = memfd;

	read_task_vmas(task, false);

	if (!task->libc_vma || !task->stack) {
		lerror("No libc or stack founded.\n");
		goto free_task;
	}

	/* Load libc ELF file if needed
	 */
	if (flag & FTO_LIBC) {
		task->libc_elf = elf_file_open(task->libc_vma->name_);
		if (!task->libc_elf) {
			lerror("Open libc failed.\n");
			goto free_task;
		}
	}
	if (flag & FTO_SELF) {
		task->exe_elf = elf_file_open(task->exe);
		if (!task->exe_elf) {
			lerror("Open exe:%s failed.\n", task->exe);
			goto free_task;
		}
	}

	/* All success, add task to global list
	 */
	list_add(&task->node, &tasks_list);

	return task;

free_task:
	free_task(task);
	return NULL;
}

int free_task(struct task *task)
{
	list_del(&task->node);
	close(task->proc_mem_fd);

	if (task->fto_flag & FTO_SELF)
		elf_file_close(task->exe);

	if (task->fto_flag & FTO_LIBC)
		elf_file_close(task->libc_vma->name_);

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

static int __unused pid_write(int pid, void *dest, const void *src, size_t len)
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

static int __unused pid_read(int pid, void *dst, const void *src, size_t len)
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

int memcpy_from_task(struct task *task,
		void *dst, unsigned long task_src, ssize_t size)
{
	int ret = -1;
	ret = pread(task->proc_mem_fd, dst, size, task_src);
	if (ret <= 0) {
		lerror("pread(%d, ...)=%d failed, %s\n",
			task->proc_mem_fd, ret, strerror(errno));
		return -errno;
	}
	return ret;
}

int memcpy_to_task(struct task *task,
		unsigned long task_dst, void *src, ssize_t size)
{
	int ret = -1;
	ret = pwrite(task->proc_mem_fd, src, size, task_dst);
	if (ret <= 0) {
		lerror("pwrite(%d, ...)=%d failed, %s\n",
			task->proc_mem_fd, ret, strerror(errno));
		memshow(src, size);
		return -errno;
	}
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

int wait_for_stop(struct task *task)
{
	int ret, status = 0;
	pid_t pid = task->pid;

	while (1) {
		ret = ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)status);
		if (ret < 0) {
			print_vma(task->libc_vma);
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

int task_syscall(struct task *task, int nr,
		unsigned long arg1, unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5, unsigned long arg6,
		unsigned long *res)
{
	int ret;
	struct user_regs_struct old_regs, regs, __unused syscall_regs;
	unsigned char __syscall[] = {SYSCALL_INSTR};

#if defined(__aarch64__)
	struct iovec orig_regs_iov, regs_iov;

	orig_regs_iov.iov_base = &old_regs;
	orig_regs_iov.iov_len = sizeof(old_regs);
	regs_iov.iov_base = &regs;
	regs_iov.iov_len = sizeof(regs);
#endif

	SYSCALL_REGS_PREPARE(syscall_regs, nr, arg1, arg2, arg3, arg4, arg5, arg6);

	unsigned char orig_code[sizeof(__syscall)];
	unsigned long libc_base = task->libc_vma->start;

#if defined(__x86_64__)
	ret = ptrace(PTRACE_GETREGS, task->pid, NULL, &old_regs);
#elif defined(__aarch64__)
	ret = ptrace(PTRACE_GETREGSET, task->pid, (void*)NT_PRSTATUS,
			(void*)&orig_regs_iov);
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
	ret = ptrace(PTRACE_GETREGSET, task->pid, (void*)NT_PRSTATUS,
			(void*)&regs_iov);
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

unsigned long task_mmap(struct task *task,
	unsigned long addr, size_t length, int prot, int flags,
	int fd, off_t offset)
{
	int ret;
	unsigned long result;

	ret = task_syscall(task,
			__NR_mmap, addr, length, prot, flags, fd, offset, &result);
	if (ret < 0) {
		return 0;
	}
	return result;
}

int task_munmap(struct task *task, unsigned long addr, size_t size)
{
	int ret;
	unsigned long result;

	ret = task_syscall(task,
			__NR_munmap, addr, size, 0, 0, 0, 0, &result);
	if (ret < 0) {
		return -1;
	}
	return result;
}

int task_msync(struct task *task, unsigned long addr, size_t length, int flags)
{
	int ret;
	unsigned long result;

	ret = task_syscall(task,
			__NR_msync, addr, length, flags, 0, 0, 0, &result);
	if (ret < 0) {
		return -1;
	}
	return result;
}

int task_msync_sync(struct task *task, unsigned long addr, size_t length)
{
	return task_msync(task, addr, length, MS_SYNC);
}
int task_msync_async(struct task *task, unsigned long addr, size_t length)
{
	return task_msync(task, addr, length, MS_ASYNC);
}

unsigned long task_malloc(struct task *task, size_t length)
{
	unsigned long remote_addr;
	remote_addr = task_mmap(task,
				0UL, length,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (remote_addr == (unsigned long)MAP_FAILED) {
		lerror("Remote malloc failed, %d\n", remote_addr);
		return 0UL;
	}
	return remote_addr;
}

int task_free(struct task *task, unsigned long addr, size_t length)
{
	return task_munmap(task, addr, length);
}

int task_open(struct task *task, char *pathname, int flags, mode_t mode)
{
	char maybeislink[MAX_PATH], path[MAX_PATH];
	int ret;
	unsigned long result;

	unsigned long remote_fileaddr;
	ssize_t remote_filename_len = 0;

	if (!(flags|O_CREAT)) {
		ret = readlink(pathname, maybeislink, sizeof(maybeislink));
		if (ret < 0) {
			lwarning("readlink(3) failed.\n");
			return -1;
		}
		maybeislink[ret] = '\0';
		if (!realpath(maybeislink, path)) {
			lwarning("realpath(3) failed.\n");
			return -1;
		}
		ldebug("%s -> %s -> %s\n", pathname, maybeislink, path);
		pathname = path;
	}
	remote_filename_len = strlen(pathname) + 1;

	remote_fileaddr = task_malloc(task, remote_filename_len);

	memcpy_to_task(task, remote_fileaddr, pathname, remote_filename_len);

#if defined(__x86_64__)
	ret = task_syscall(task,
			__NR_open, remote_fileaddr, flags, mode, 0, 0, 0, &result);
#elif defined(__aarch64__)
	ret = task_syscall(task,
			__NR_openat, AT_FDCWD, remote_fileaddr, flags, mode, 0, 0, &result);
#else
# error "Error arch"
#endif

	task_free(task, remote_fileaddr, remote_filename_len);

	return result;
}

int task_close(struct task *task, int remote_fd)
{
	int ret;
	unsigned long result;
	ret = task_syscall(task,
			__NR_close, remote_fd, 0, 0, 0, 0, 0, &result);
	if (ret < 0) {
		return 0;
	}
	return result;
}

int task_ftruncate(struct task *task, int remote_fd, off_t length)
{
	int ret;
	unsigned long result;
	ret = task_syscall(task,
			__NR_ftruncate, remote_fd, length, 0, 0, 0, 0, &result);
	if (ret < 0) {
		return 0;
	}
	return result;
}

int task_fstat(struct task *task, int remote_fd, struct stat *statbuf)
{
	int ret, ret_fstat;
	unsigned long remote_statbuf;
	unsigned long result;

	/* Alloc stat struct from remote */
	remote_statbuf = task_malloc(task, sizeof(struct stat));

	/* Call fstat(2) */
	ret_fstat = task_syscall(task,
			__NR_fstat, remote_fd, remote_statbuf, 0, 0, 0, 0, &result);
	if (ret_fstat < 0) {
		lerror("fstat failed, ret %d, %ld\n", ret_fstat, result);
	}

	ret = memcpy_from_task(task, statbuf, remote_statbuf, sizeof(struct stat));
	if (ret != sizeof(struct stat)) {
		lerror("failed copy struct stat.\n");
	}
	task_free(task, remote_statbuf, sizeof(struct stat));

	return ret_fstat;
}

int task_prctl(struct task *task, int option, unsigned long arg2,
	unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	int ret;
	unsigned long result;

	ret = task_syscall(task,
		__NR_prctl, option, arg2, arg3, arg4, arg5, 0, &result);
	if (ret < 0) {
		return 0;
	}
	return result;
}


/* task_wait inner message?
 *
 */
struct msg_form {
	int mtype;
	char mtext[32];
};

#define PROG_ID	123

/* key: ftok(2) open/create a tmp file
 */
int task_wait_init(struct task_wait *task_wait, char *tmpfile)
{
	int fd;

	sprintf(task_wait->tmpfile, tmpfile?:"/tmp/key-XXXXXXX");

	if (tmpfile)
		return 0;

	fd = mkstemp(task_wait->tmpfile);
	if (fd <= 0) {
		fprintf(stderr, "mkstemp: %s\n", strerror(errno));
		return -errno;
	}
	close(fd);

	return 0;
}

int task_wait_destroy(struct task_wait *task_wait)
{
	unlink(task_wait->tmpfile);
	return 0;
}

int task_wait_wait(struct task_wait *task_wait)
{
	int msqid;
	key_t key;

	struct msg_form msg;

	if ((key = ftok(task_wait->tmpfile, PROG_ID)) < 0) {
		perror("ftok error");
		exit(1);
	}

	if ((msqid = msgget(key, IPC_CREAT | 0777)) == -1) {
		perror("msgget error");
		exit(1);
	}

	msgrcv(msqid, &msg, sizeof(msg), msg.mtype, 0);

	msgctl(msqid, IPC_RMID, NULL);

	return 0;
}

int task_wait_trigger(struct task_wait *task_wait, useconds_t usec)
{
	int msqid;
	key_t key;
	struct msg_form msg = {
		.mtype = 0,
		.mtext = {0},
	};

	if ((key = ftok(task_wait->tmpfile, PROG_ID)) < 0) {
		perror("ftok error");
		exit(1);
	}

	if ((msqid = msgget(key, IPC_CREAT | 0777)) == -1) {
		perror("msgget error");
		exit(1);
	}

	// Do you need sleep for a while
	if (usec)
		usleep(usec);

	msg.mtext[0] = 'q';
	msgsnd(msqid, &msg, sizeof(msg), 0);

	msgctl(msqid, IPC_RMID, NULL);

	return 0;
}

