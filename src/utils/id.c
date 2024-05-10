// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <utils/util.h>

bool is_root(const char *prog)
{
	if (geteuid() == 0)
		return true;
	return false;
}

