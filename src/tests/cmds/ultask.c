// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <utils/log.h>
#include <utils/cmds.h>

#include <tests/test-api.h>


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
	int argc = 2;
	char *argv[] = {"ultask", "--info"};
	return ultask(argc, argv);
}
