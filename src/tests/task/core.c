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


TEST(Task, fto_flags, 0)
{
	int ret = 0;
	char buffer[PATH_MAX];

	struct task_struct *task = open_task(getpid(), FTO_ALL);

	/* ULP_PROC_ROOT_DIR/PID */
	snprintf(buffer, PATH_MAX - 1, ULP_PROC_ROOT_DIR "/%d", task->pid);
	if (!fexist(buffer)) {
		ret = -1;
	}

	/* ULP_PROC_ROOT_DIR/PID/TASK_PROC_COMM */
	snprintf(buffer, PATH_MAX - 1,
		ULP_PROC_ROOT_DIR "/%d/" TASK_PROC_COMM, task->pid);
	if (!fexist(buffer)) {
		ret = -1;
	}

	/* ULP_PROC_ROOT_DIR/PID/patches */
	snprintf(buffer, PATH_MAX - 1,
		ULP_PROC_ROOT_DIR "/%d/" TASK_PROC_MAP_FILES, task->pid);
	if (!fexist(buffer)) {
		ret = -1;
	}

	dump_task_vmas(stdout, task, true);

	close_task(task);

	return ret;
}

TEST(Task, open_failed, -1)
{
	/**
	 * Try to open pid 0 (idle)
	 */
	struct task_struct *task = open_task(0, FTO_NONE);
	return task ? 0 : -1;
}

TEST(Task, open_non_exist, -1)
{
	/**
	 * Try to open pid -1 (non exist)
	 */
	struct task_struct *task = open_task(-1, FTO_NONE);
	return task ? 0 : -1;
}

TEST(Task, dump, 0)
{
	struct task_struct *task = open_task(getpid(), FTO_NONE);
	dump_task(stdout, task, true);
	dump_task_vmas(stdout, task, true);
	return close_task(task);
}

TEST(Task, attach_detach, 0)
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

	ret = 0;
	ret += task_attach(pid);
	ret += task_detach(pid);

	task_notify_trigger(&notify);

	waitpid(pid, &status, __WALL);
	if (status != 0) {
		ret = -EINVAL;
	}

	task_notify_destroy(&notify);

	return ret;
}
