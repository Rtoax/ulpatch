// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <utils/log.h>
#include <utils/cmds.h>

#include <tests/test-api.h>

TEST_STUB(cmds_ulpinfo);

TEST(ulpinfo, version, 0)
{
	int argc = 2;
	char *argv[] = {"ulpinfo", "--version"};
	char *argv2[] = {"ulpinfo", "-V"};
	return ulpinfo(argc, argv) + ulpinfo(argc, argv2);
}

TEST(ulpinfo, help, 0)
{
	int argc = 2;
	char *argv[] = {"ulpinfo", "--help"};
	char *argv2[] = {"ulpinfo", "-h"};
	return ulpinfo(argc, argv) + ulpinfo(argc, argv2);
}

TEST(ulpinfo, info, 0)
{
	int argc = 2;
	char *argv[] = {"ulpinfo", "--info"};
	return ulpinfo(argc, argv);
}
