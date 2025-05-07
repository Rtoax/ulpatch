// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024-2025 Rong Tao */
#include <utils/log.h>
#include <utils/cmds.h>

#include <tests/test-api.h>


TEST(ulpatch, display, 0)
{
	int ret = 0;
	char *argv[] = { "ulpatch", "--map-pfx", };
	ret += ulpatch(2, argv);
	return ret;
}
