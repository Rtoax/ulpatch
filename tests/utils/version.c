// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <sys/types.h>
#include <unistd.h>

#include <utils/log.h>
#include <utils/list.h>

#include "../test_api.h"


TEST(Utils,	elftools_version,	0)
{
	printf("%s\n", elftools_version());
	return 0;
}

