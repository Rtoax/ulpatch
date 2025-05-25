// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <sys/types.h>
#include <unistd.h>
#include "utils/log.h"
#include "utils/util.h"
#include "utils/list.h"
#include "tests/test-api.h"


TEST(Utils_init, dry_run, 0)
{
	int ret = 0;

	if (is_dry_run())
		ret = EINVAL;

	return ret;
}

TEST(Utils_init, verbose, 0)
{
	int ret = 0;

	if (is_verbose())
		ret = EINVAL;

	return ret;
}
