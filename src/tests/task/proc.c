// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>

#include <utils/log.h>
#include <utils/list.h>
#include <task/task.h>
#include <tests/test-api.h>

TEST_STUB(task_proc);

TEST(Utils_task_proc, get_proc_pid_exe, 0)
{
	char buf[256], *exe;

	if ((exe = get_proc_pid_exe(getpid(), buf, sizeof(buf))) != NULL) {
		ulp_debug("exe: <%s>\n", exe);
		return 0;
	}
	return -1;
}

TEST(Utils_task_proc, open_pid_maps, 0)
{
	int fd;
	fd = open_pid_maps(getpid());
	fprint_fd(stdout, fd);
	close(fd);
	return 0;
}

