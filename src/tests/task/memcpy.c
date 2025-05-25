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


TEST(Task, copy_from_task, 0)
{
	char data[] = "ABCDEFGH";
	char buf[64] = "XXXXXXXX";
	int ret = 0;
	int n;

	struct task_struct *task = open_task(getpid(), FTO_NONE);

	ulp_debug("memcpy_from_task: %s\n", buf);
	n = memcpy_from_task(task, buf, (unsigned long)data, strlen(data) + 1);

	if (n == -1 || n != strlen(data) + 1 || strcmp(data, buf))
		ret = -1;

	close_task(task);
	return ret;
}

TEST(Task, copy_to_task, 0)
{
	char data[] = "ABCDEFG";
	char buf[64] = "XXXXXX";
	int ret = 0;
	int n;

	struct task_struct *task = open_task(getpid(), FTO_RDWR);

	n = memcpy_to_task(task, (unsigned long)buf, data, strlen(data) + 1);

	if (n != strlen(data) + 1 || strcmp(data, buf))
		ret = -1;

	close_task(task);
	return ret;
}

TEST(Task, task_strcpy, 0)
{
	char data[] = "ABCDEFGH\0";
	char buf[64] = "XXXXXXXX";
	char buf2[64] = "XXXXXXXX";
	int ret = 0;
	char *s = NULL;

	struct task_struct *task = open_task(getpid(), FTO_RDWR);

	s = strcpy_to_task(task, (unsigned long)buf, data);
	if (s != data || strcmp(data, buf))
		ret = -1;

	s = strcpy_from_task(task, buf2, (unsigned long)data);
	if (s != buf2 || strcmp(data, buf2))
		ret = -1;

	close_task(task);
	return ret;
}

TEST(Task, mmap_malloc, 0)
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

	dump_task_vmas(stdout, task, true);

	n = memcpy_to_task(task, addr, data, strlen(data) + 1);
	ulp_debug("memcpy_from_task: %s\n", buf);
	n = memcpy_from_task(task, buf, addr, strlen(data) + 1);
	/* memcpy failed */
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
