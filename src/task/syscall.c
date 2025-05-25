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

#if defined(__x86_64__)
#include "arch/x86_64/regs.h"
#include "arch/x86_64/instruments.h"
#elif defined(__aarch64__)
#include "arch/aarch64/regs.h"
#include "arch/aarch64/instruments.h"
#endif


#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wuninitialized"
#elif defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wuninitialized"
# pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
static void copy_regs(struct user_regs_struct *dst,
		      struct user_regs_struct *src)
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
# pragma clang diagnostic pop
#elif defined(__GNUC__)
# pragma GCC diagnostic pop
#endif

int wait_for_stop(struct task_struct *task)
{
	int ret, status = 0;
	pid_t pid = task->pid;

	while (1) {
		ret = ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)status);
		if (ret < 0) {
			print_vma(stderr, true, task->vma_root.libc_code, false);
			ulp_error("ptrace(PTRACE_CONT, %d, ...) %m\n", pid);
			return -1;
		}

		ret = waitpid(pid, &status, __WALL);
		if (ret < 0) {
			ulp_error("can't wait tracee %d\n", pid);
			return -1;
		}
		if (WIFSTOPPED(status)) {
			if (WSTOPSIG(status) == SIGSTOP ||
				WSTOPSIG(status) == SIGTRAP) {
				break;
			}
			if (WSTOPSIG(status) == SIGSEGV) {
				ulp_error("Child process %d segment fault.\n",
					  pid);
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
	unsigned long libc_base = task->vma_root.libc_code->vm_start;

	memset(&syscall_regs, 0x0, sizeof(syscall_regs));

#if defined(__aarch64__)
	struct iovec orig_regs_iov, regs_iov;

	orig_regs_iov.iov_base = &old_regs;
	orig_regs_iov.iov_len = sizeof(old_regs);
	regs_iov.iov_base = &regs;
	regs_iov.iov_len = sizeof(regs);
#endif

	SYSCALL_REGS_PREPARE(syscall_regs, nr, arg1, arg2, arg3, arg4, arg5,
		      arg6);

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
		ulp_error("ptrace(PTRACE_GETREGS, %d, ...) failed, %m\n",
			task->pid);
		if (is_verbose())
			do_backtrace(stdout);
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
		ulp_error("ptrace(PTRACE_SETREGS, %d, ...) failed, %m\n",
			task->pid);
		ret = -errno;
		goto poke_back;
	}

	ret = wait_for_stop(task);
	if (ret < 0) {
		ulp_error("failed call to func\n");
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
		ulp_error("ptrace(PTRACE_GETREGS, %d, ...) failed, %m\n",
			task->pid);
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
		ulp_error("ptrace(PTRACE_SETREGS, %d, ...) failed, %m\n",
			task->pid);
		ret = -errno;
		goto poke_back;
	}

	syscall_regs = regs;
	*res = SYSCALL_RET(syscall_regs);

	ulp_debug("result %lx\n", *res);

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

int task_mprotect(struct task_struct *task, unsigned long addr, size_t len,
		  int prot)
{
	int ret;
	unsigned long result;

	ret = task_syscall(task, __NR_mprotect, addr, len, prot, 0, 0, 0,
			   &result);
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
		ulp_error("Remote malloc failed, %ld\n", remote_addr);
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

int task_open2(struct task_struct *task, char *pathname, int flags)
{
	return task_open(task, pathname, flags, 0);
}

/* There are some file descriptors we should never close them. */
static bool __should_skip_remote_fd(int remote_fd)
{
	int fd = remote_fd;
	/* We should never close 0,1,2 fd of target process. */
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
		ulp_warning("Try to close remote 0,1,2 file descriptor.\n");
		return true;
	}
	/**
	 * TODO: ULPatch should never close target process fd, which was
	 * created by target process own.
	 */
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
		ulp_error("fstat failed, ret %d, %ld\n", ret_fstat, result);

	ret = memcpy_from_task(task, statbuf, remote_statbuf,
			sizeof(struct stat));
	if (ret == -1 || ret != sizeof(struct stat))
		ulp_error("failed copy struct stat.\n");

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

