// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ptrace.h>

#include "utils/log.h"
#include "task/task.h"


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

int dump_task_addr_to_file(const char *ofile, struct task_struct *task,
			   unsigned long addr, unsigned long size)
{
	void *mem = NULL;
	int nbytes;
	struct vm_area_struct *vma;

	/**
	 * If no output file name is specified, then the default output to
	 * stdout can be output using redirection.
	 */
	int fd = fileno(stdout);

	vma = find_vma(task, addr);
	if (!vma) {
		ulp_error("comm '%s'(pid=%d) invalid memory address 0x%lx.\n",
			  task->comm, task->pid, addr);
		return -ENOENT;
	}

	if (ofile) {
		fd = open(ofile, O_CREAT | O_RDWR, 0664);
		if (fd <= 0) {
			ulp_error("open %s: %m\n", ofile);
			return -errno;
		}
	}

	mem = malloc(size);

	memcpy_from_task(task, mem, addr, size);

	/* write to file or stdout */
	nbytes = write(fd, mem, size);
	if (nbytes != size) {
		ulp_error("write failed, %m.\n");
		free(mem);
		return -errno;
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
		return -ENOENT;
	}

	vma_size = vma->vm_end - vma->vm_start;

	return dump_task_addr_to_file(ofile, task, vma->vm_start, vma_size);
}
