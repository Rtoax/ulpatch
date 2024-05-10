// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <utils/log.h>
#include <utils/list.h>

#include <tests/test_api.h>


TEST(Id,	is_root,	0)
{
	if (is_root("PROG"))
		ldebug("Run with root.\n");
	return 0;
}

