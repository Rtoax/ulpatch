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


int open_pid_maps(pid_t pid)
{
	int mapsfd;
	char maps[] = "/proc/1234567890/maps";

	snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
	mapsfd = open(maps, O_RDONLY);
	if (mapsfd <= 0) {
		ulp_error("open %s failed. %m\n", maps);
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
		ulp_error("open %s failed. %m\n", mem);
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

	memset(buf, 0x0, bufsz);
	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	ret = readlink(path, buf, bufsz);
	if (ret < 0) {
		ulp_error("readlink %s failed, %m\n", path);
		return NULL;
	}
	return buf;
}

char *get_proc_pid_cwd(pid_t pid, char *buf, size_t bufsz)
{
	ssize_t ret = 0;
	char path[PATH_MAX];

	memset(buf, 0x0, bufsz);
	snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
	ret = readlink(path, buf, bufsz);
	if (ret < 0) {
		ulp_error("readlink %s failed, %m\n", path);
		return NULL;
	}
	return buf;
}

int proc_get_comm(struct task_struct *task)
{
	char path[PATH_MAX];
	int ret;
	FILE *fp = NULL;

	ret = snprintf(path, sizeof(path), "/proc/%d/comm", task->pid);
	if (ret < 0) {
		ulp_error("readlink %s failed, %m\n", path);
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

int proc_get_exe(struct task_struct *task)
{
	char path[PATH_MAX], realpath[PATH_MAX];
	ssize_t ret;

	snprintf(path, sizeof(path), "/proc/%d/exe", task->pid);
	ret = readlink(path, realpath, sizeof(realpath));
	if (ret < 0) {
		ulp_error("readlink %s failed, %m\n", path);
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

int proc_get_pid_status(pid_t pid, struct task_status *status)
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
		ulp_error("Open %s failed, %m\n", buf);
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

	fprintf(fp, "Uid:\t%d\t%d\t%d\t%d\n", ps->uid, ps->euid, ps->suid,
		ps->fsuid);
	fprintf(fp, "Gid:\t%d\t%d\t%d\t%d\n", ps->gid, ps->egid, ps->sgid,
		ps->fsgid);
	return 0;
}
