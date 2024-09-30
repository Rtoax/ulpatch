// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <utils/log.h>
#include <utils/cmds.h>

#include <tests/test-api.h>

TEST_STUB(cmds_ulpinfo);

TEST(ulpinfo, objects, 0)
{
	int i, ret = 0;

	for (i = 0; i < nr_ulpatch_objs(); i++) {
		char *obj = ulpatch_objs[i].path;
		int argc = 3;
		char *argv[] = { "ulpinfo", "-i", obj, };
		char *argv2[] = { "ulpinfo", "--patch", obj, };

		printf("\n");
		ret += ulpinfo(argc, argv);
		printf("\n");
		ret += ulpinfo(argc, argv2);
	}
	return ret;
}
