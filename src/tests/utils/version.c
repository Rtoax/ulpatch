// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <sys/types.h>
#include <unistd.h>

#include <utils/log.h>
#include <utils/list.h>

#include "../test_api.h"


TEST(Utils,	upatch_version,	0)
{
	int ret = 0;

	ret += upatch_version_major() != UPATCH_VERSION_MAJOR;
	ret += upatch_version_minor() != UPATCH_VERSION_MINOR;
	ret += upatch_version_patch() != UPATCH_VERSION_PATCH;

	printf("%s\n", upatch_version());
	return ret;
}

