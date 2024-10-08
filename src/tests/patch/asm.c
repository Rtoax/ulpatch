// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <errno.h>
#include <sys/wait.h>

#include <utils/log.h>
#include <utils/util.h>
#include <patch/asm.h>

#include <tests/test-api.h>

TEST_STUB(patch_asm);

TEST(Patch_asm, sleep, 0)
{
	ASM_SLEEP(1);
	return 0;
}

TEST(Patch_asm, write, 0)
{
	char msg[] = {"Hello-\n"};
	int len = 7;
	ASM_WRITE(1, msg, len);
	ASM_WRITE_HELLO();
	return 0;
}

TEST(Patch_asm, exit, 0)
{
	int pid, status;
	int ret = 0;
#define EXIT_VAL	0xff

	pid = fork();
	if (pid == 0)
		ASM_EXIT(EXIT_VAL);
	else {
		waitpid(pid, &status, 0);
		if (WEXITSTATUS(status) != EXIT_VAL)
			ret = 1;
	}

	return ret;
}
