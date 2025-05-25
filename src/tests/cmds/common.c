// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024-2025 Rong Tao */
#include "utils/compiler.h"
#include "utils/log.h"
#include "cmds.h"

#include "tests/test-api.h"


static struct cmd {
	char *name;
	int (*func)(int argc, char *argv[]);
} cmds[] __unused = {
#ifdef CONFIG_BUILD_ULFTRACE
	{ "ulftrace", ulftrace },
#endif
	{ "ulpatch", ulpatch },
	{ "ulpinfo", ulpinfo },
#ifdef CONFIG_BUILD_ULTASK
	{ "ultask", ultask },
#endif
};

TEST(Cmds_common, version, 0)
{
	int i, ret = 0;
	struct cmd *cmd;

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		cmd = &cmds[i];
		int argc = 2;
		char *argv[] = { cmd->name, "--version" };
		char *argv2[] = { cmd->name, "-V" };
		ret += cmd->func(argc, argv) + cmd->func(argc, argv2);
	}

	return ret;
}

TEST(Cmds_common, help, 0)
{
	int i, ret = 0;
	struct cmd *cmd;

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		cmd = &cmds[i];
		int argc = 2;
		char *argv[] = { cmd->name, "--help" };
		char *argv2[] = { cmd->name, "-h" };
		ret += cmd->func(argc, argv) + cmd->func(argc, argv2);
	}

	return ret;
}

TEST(Cmds_common, info_misc, 0)
{
	int i, ret = 0;
	struct cmd *cmd;

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		cmd = &cmds[i];
		int argc = 2;
		char *argv[] = { cmd->name, "--info" };
		int argc2 = 3;
		char *argv2[] = { cmd->name, "--verbose", "--info" };
		int argc3 = 3;
		char *argv3[] = { cmd->name, "-v", "--info" };
		int argc4 = 3;
		char *argv4[] = { cmd->name, "-vvvvv", "--info" };
		ret += cmd->func(argc, argv) + cmd->func(argc2, argv2) +
			cmd->func(argc3, argv3) + cmd->func(argc4, argv4);
	}

	return ret;
}
