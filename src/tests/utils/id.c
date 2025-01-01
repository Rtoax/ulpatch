// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <utils/log.h>
#include <utils/list.h>

#include <tests/test-api.h>

TEST_STUB(utils_id);

TEST(Utils_id, is_root, 0)
{
	if (is_root("PROG"))
		ulp_debug("Run with root.\n");
	return 0;
}

