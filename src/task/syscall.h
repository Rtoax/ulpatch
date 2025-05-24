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

struct task_struct;

/* syscalls based on task_syscall() */
/* if mmap file, need to update_task_vmas_ulp() manual */
unsigned long task_mmap(struct task_struct *task, unsigned long addr,
			size_t length, int prot, int flags, int fd,
			off_t offset);
int task_munmap(struct task_struct *task, unsigned long addr, size_t size);
int task_mprotect(struct task_struct *task, unsigned long addr, size_t len,
		  int prot);
int task_msync(struct task_struct *task, unsigned long addr, size_t length,
	       int flags);
int task_msync_sync(struct task_struct *task, unsigned long addr,
		    size_t length);
int task_msync_async(struct task_struct *task, unsigned long addr,
		     size_t length);
unsigned long task_malloc(struct task_struct *task, size_t length);
int task_free(struct task_struct *task, unsigned long addr, size_t length);
int task_open(struct task_struct *task, char *pathname, int flags, mode_t mode);
int task_open2(struct task_struct *task, char *pathname, int flags);
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
