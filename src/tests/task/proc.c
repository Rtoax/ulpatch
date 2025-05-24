// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
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


TEST(Task_proc, proc_pid_exe, 0)
{
	int ret = 0;
	char buf[256];
	const char *exe;

	if ((exe = proc_pid_exe(getpid(), buf, sizeof(buf))) == NULL) {
		ulp_error("get pid %d exe failed.\n", getpid());
		ret = -1;
	} else
		fprintf(stdout, "exe = %s\n", exe);

	return ret;
}

TEST(Task_proc, proc_pid_cwd, 0)
{
	char buf[256], *cwd;
	char buf2[256], *cwd2;

	cwd = proc_pid_cwd(getpid(), buf, sizeof(buf));
	cwd2 = getcwd(buf2, sizeof(buf2));

	fprintf(stdout, "cwd = %s\n", cwd);
	fprintf(stdout, "cwd2 = %s\n", cwd2);

	return strcmp(cwd, cwd2);
}

TEST(Task_proc, open_pid_maps, 0)
{
	int fd;
	fd = open_pid_maps(getpid());
	fprint_fd(stdout, fd);
	close(fd);
	return 0;
}
