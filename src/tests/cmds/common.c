// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <utils/compiler.h>
#include <utils/log.h>
#include <utils/cmds.h>

#include <tests/test-api.h>

TEST_STUB(cmds_common);

static struct cmd {
	char *name;
	int (*func)(int argc, char *argv[]);
} cmds[] __unused = {
	{ "ulftrace", ulftrace },
	{ "ulpatch", ulpatch },
	{ "ulpinfo", ulpinfo },
	{ "ultask", ultask },
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

TEST(Cmds_common, info, 0)
{
	int i, ret = 0;
	struct cmd *cmd;

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		cmd = &cmds[i];
		int argc = 2;
		char *argv[] = { cmd->name, "--info" };
		int argc2 = 3;
		char *argv2[] = { cmd->name, "--info", "-vvvv" };
		ret += cmd->func(argc, argv) + cmd->func(argc2, argv2);
	}

	return ret;
}

