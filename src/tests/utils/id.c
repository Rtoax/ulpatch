// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#include "utils/log.h"
#include "utils/list.h"
#include "utils/macros.h"
#include "utils/utils.h"

#include "tests/test-api.h"


TEST(Utils_id, is_root, 0)
{
	if (is_root("PROG"))
		ulp_debug("Run with root.\n");
	return 0;
}
