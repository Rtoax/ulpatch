// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <utils/log.h>
#include <utils/cmds.h>

#include <tests/test-api.h>


TEST(ulftrace, version, 0)
{
	int argc = 2;
	char *argv[] = {"ulftrace", "--version"};
	char *argv2[] = {"ulftrace", "-V"};
	return ulftrace(argc, argv) + ulftrace(argc, argv2);
}

TEST(ulftrace, help, 0)
{
	int argc = 2;
	char *argv[] = {"ulftrace", "--help"};
	char *argv2[] = {"ulftrace", "-h"};
	return ulftrace(argc, argv) + ulftrace(argc, argv2);
}

TEST(ulftrace, info, 0)
{
	int argc = 2;
	char *argv[] = {"ulftrace", "--info"};
	return ulftrace(argc, argv);
}

