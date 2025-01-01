// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024-2025 Rong Tao */
#include <errno.h>
#include <sys/wait.h>

#include <utils/log.h>
#include <utils/util.h>
#include <patch/asm.h>

#include <tests/test-api.h>

TEST_STUB(patch_asm);

TEST(Patch_asm, sleep, 0)
{
	__ulp_builtin_sleep(1);
	return 0;
}

TEST(Patch_asm, write, 0)
{
	char msg[] = {"Hello-\n"};
	int len = 7;
	__ulp_builtin_write(1, msg, len);
	__ulp_builtin_write_hello();
	return 0;
}

TEST(Patch_asm, exit, 0)
{
	int pid, status;
	int ret = 0;
#define EXIT_VAL	0xff

	pid = fork();
	if (pid == 0)
		__ulp_builtin_exit(EXIT_VAL);
	else {
		waitpid(pid, &status, 0);
		if (WEXITSTATUS(status) != EXIT_VAL)
			ret = 1;
	}

	return ret;
}
