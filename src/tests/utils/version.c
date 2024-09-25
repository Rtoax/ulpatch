// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <sys/types.h>
#include <unistd.h>

#include <utils/log.h>
#include <utils/list.h>
#include <tests/test-api.h>

TEST_STUB(utils_version);

TEST(Utils_version, ulpatch_version, 0)
{
	int ret = 0;

	ret += ulpatch_version_major() != ULPATCH_VERSION_MAJOR;
	ret += ulpatch_version_minor() != ULPATCH_VERSION_MINOR;
	ret += ulpatch_version_patch() != ULPATCH_VERSION_PATCH;

	printf("%s\n", ulpatch_version());
	return ret;
}

