// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <sys/types.h>
#include <unistd.h>
#include <utils/log.h>
#include <utils/util.h>
#include <utils/list.h>
#include <tests/test-api.h>

TEST_STUB(utils_init);

TEST(Utils, dry_run, 0)
{
	int ret = 0;

	if (is_dry_run())
		ret = EINVAL;

	return ret;
}

TEST(Utils, verbose, 0)
{
	int ret = 0;

	if (is_verbose())
		ret = EINVAL;

	return ret;
}

