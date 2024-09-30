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

