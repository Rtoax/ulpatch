// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once
#include <sys/stat.h>
#include <sys/types.h>

struct task_status {
	/**
	 * Get from /proc/[pid]/status
	 */
	uid_t uid, euid, suid, fsuid;
	gid_t gid, egid, sgid, fsgid;
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


