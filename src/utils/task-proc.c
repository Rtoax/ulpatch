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
#include <utils/task.h>


int open_pid_maps(pid_t pid)
{
	int mapsfd;
	char maps[] = "/proc/1234567890/maps";

	snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
	mapsfd = open(maps, O_RDONLY);
	if (mapsfd <= 0) {
		ulp_error("open %s failed. %s\n", maps, strerror(errno));
		mapsfd = -1;
	}
	return mapsfd;
}

int __open_pid_mem(pid_t pid, int flags)
{
	char mem[] = "/proc/1234567890/mem";
	snprintf(mem, sizeof(mem), "/proc/%d/mem", pid);
	int memfd = open(mem, flags);
	if (memfd <= 0) {
		ulp_error("open %s failed. %s\n", mem, strerror(errno));
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

