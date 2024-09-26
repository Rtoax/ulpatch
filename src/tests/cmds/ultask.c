// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <utils/log.h>
#include <utils/cmds.h>

#include <tests/test-api.h>

TEST_STUB(cmds_ultask);


TEST(ultask, version, 0)
{
	int argc = 2;
	char *argv[] = {"ultask", "--version"};
	char *argv2[] = {"ultask", "-V"};
	return ultask(argc, argv) + ultask(argc, argv2);
}

TEST(ultask, help, 0)
{
	int argc = 2;
	char *argv[] = {"ultask", "--help"};
	char *argv2[] = {"ultask", "-h"};
	return ultask(argc, argv) + ultask(argc, argv2);
}

TEST(ultask, info, 0)
{
	int ret;
	int verbose = get_verbose();

	int argc = 2;
	char *argv[] = {"ultask", "--info"};
	int argc2 = 3;
	char *argv2[] = {"ultask", "-vvvv", "--info"};

	ret = ultask(argc, argv) + ultask(argc2, argv2);

	enable_verbose(verbose);
	return ret;
}
