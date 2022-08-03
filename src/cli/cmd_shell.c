// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#include <cli/cli_api.h>
#include <elf/elf_api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>

#include "cli-usdt.h"


static int client_execve(int argc, char *argv[])
{
	int ret = 0;
	int status = 0;
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	} else if (pid > 0) {
		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
	} else {
		lerror("vfork(2) error.\n");
	}
	return ret;
}

int cli_cmd_shell(int argc, char *argv[])
{
	if (argc < 2) {
		printf("help SHELL: to show help.\n");
	} else if (argc >= 2) {
		int _argc = argc - 1;
		char **_argv = argv + 1;

		trace_cli_shell(_argv[0]);

		return client_execve(_argc, _argv);
	}

	return -ENOENT;
}

