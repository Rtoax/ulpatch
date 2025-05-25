// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>

#include "utils/log.h"
#include "utils/list.h"
#include "task/task.h"
#include "tests/test-api.h"


TEST(Task, fstat, 0)
{
	int ret = 0;
	int status = 0;
	struct task_notify notify;
	int remote_fd, local_fd;
	struct stat stat = {};
	struct stat statbuf = {};

	task_notify_init(&notify, NULL);

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			(char*)ulpatch_test_path,
			"--role", "sleeper,trigger,sleeper,wait",
			"--msgq", notify.tmpfile,
			NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	}

	/* Parent */
	task_notify_wait(&notify);

	struct task_struct *task = open_task(pid, FTO_RDWR);
	char *filename = "/usr/bin/ls";

	ret = task_attach(pid);
	remote_fd = task_open(task, filename, O_RDONLY, 0644);
	if (remote_fd <= 0) {
		ulp_warning("remote open failed.\n");
		return -1;
	}
	local_fd = open(filename, O_RDONLY, 0644);
	if (local_fd <= 0) {
		ulp_warning("open failed.\n");
		return -1;
	}

	fstat(local_fd, &stat);
	ret = task_fstat(task, remote_fd, &statbuf);

	if (stat.st_size != statbuf.st_size) {
		ulp_error("st_size not equal: remote(%ld) vs local(%ld)\n",
			statbuf.st_size, stat.st_size);
		ret = -1;
	}

	ulp_debug("stat.st_size = %ld\n", statbuf.st_size);

	task_close(task, remote_fd);
	task_detach(pid);

	task_notify_trigger(&notify);
	waitpid(pid, &status, __WALL);
	if (status != 0) {
		ret = -EINVAL;
	}
	close_task(task);

	task_notify_destroy(&notify);

	ulp_debug("ret = %d\n", ret);

	return ret;
}

static int test_mmap_file(struct task_struct *task, int prot)
{
	int ret = 0;
	unsigned long map_v;
	ssize_t map_len = 8192;
	int __unused map_fd;
	char filename[] = "todo.txt";

	map_fd = task_open(task, filename, O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (map_fd <= 0) {
		ulp_warning("remote open failed.\n");
		return -1;
	}
	ulp_debug("New open. %d\n", map_fd);
	ret = task_ftruncate(task, map_fd, map_len);
	if (ret != 0) {
		ulp_warning("remote ftruncate failed.\n");
		goto close_ret;
	}
	map_v = task_mmap(task,
				0UL, map_len,
				prot,
				MAP_PRIVATE, map_fd, 0);
	ulp_debug("New mmap. %lx\n", map_v);

	update_task_vmas_ulp(task);
	print_vma_root(stdout, &task->vma_root, true);

	ulp_debug("unmmap. %lx\n", map_v);
	task_munmap(task, map_v, map_len);

	unlink(filename);

close_ret:
	task_close(task, map_fd);

	return ret;
}

static int task_mmap_file(int prot)
{
	int ret = -1;
	int status = 0;
	struct task_notify notify;

	task_notify_init(&notify, NULL);

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			(char*)ulpatch_test_path,
			"--role", "sleeper,trigger,sleeper,wait",
			"--msgq", notify.tmpfile,
			NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	}

	/* Parent */
	task_notify_wait(&notify);

	struct task_struct *task = open_task(pid, FTO_RDWR);

	print_vma_root(stdout, &task->vma_root, true);

	ret += task_attach(pid);
	ret = test_mmap_file(task, prot);

	task_detach(pid);

	task_notify_trigger(&notify);
	waitpid(pid, &status, __WALL);
	if (status != 0) {
		ret = -EINVAL;
	}
	close_task(task);

	task_notify_destroy(&notify);

	return ret;
}

TEST(Task, mmap_file_rw, 0)
{
	return task_mmap_file(PROT_READ | PROT_WRITE);
}

TEST(Task, mmap_file_rwx, 0)
{
	return task_mmap_file(PROT_READ | PROT_WRITE | PROT_EXEC);
}

TEST(Task, prctl_PR_SET_NAME, 0)
{
	int ret = -1;
	int status = 0;
	struct task_notify notify;
	char data[] = "ABCDEFG";
	char buf[64] = "XXXXXX";
	int n;
	unsigned long addr;


	task_notify_init(&notify, NULL);

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			(char*)ulpatch_test_path,
			"--role", "sleeper,trigger,sleeper,wait",
			"--msgq", notify.tmpfile,
			NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	}

	/* Parent */
	task_notify_wait(&notify);

	struct task_struct *task = open_task(pid, FTO_RDWR);

	ret = task_attach(pid);

	addr = task_malloc(task, 64);
	ulp_debug("task %p, addr = %lx\n", task, addr);

	print_vma_root(stdout, &task->vma_root, true);

	n = memcpy_to_task(task, addr, data, strlen(data) + 1);

	/* Set thread name */
	ret = task_prctl(task, PR_SET_NAME, addr, 0, 0, 0);

	n = memcpy_from_task(task, buf, addr, strlen(data) + 1);
	if (n == -1 || n != strlen(data) + 1 || strcmp(data, buf))
		ret = -1;

	task_free(task, addr, 64);

	ret = task_detach(pid);

	task_notify_trigger(&notify);
	waitpid(pid, &status, __WALL);
	if (status != 0)
		ret = -EINVAL;
	close_task(task);

	task_notify_destroy(&notify);

	return ret;
}
