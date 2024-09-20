// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <utils/log.h>
#include <utils/cmds.h>

#include <tests/test-api.h>


TEST(ulpatch, version, 0)
{
	int argc = 2;
	char *argv[] = {"ulpatch", "--version"};
	char *argv2[] = {"ulpatch", "-V"};
	return ulpatch(argc, argv) + ulpatch(argc, argv2);
}

TEST(ulpatch, help, 0)
{
	int argc = 2;
	char *argv[] = {"ulpatch", "--help"};
	char *argv2[] = {"ulpatch", "-h"};
	return ulpatch(argc, argv) + ulpatch(argc, argv2);
}
