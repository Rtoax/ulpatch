// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <sys/types.h>
#include <unistd.h>
#include <utils/log.h>
#include <utils/util.h>
#include <utils/list.h>
#include <tests/test_api.h>

TEST(Utils,	page,	0)
{
	printf("PAGE_SIZE = %x, %lx\n", ulp_page_size(), PAGE_SIZE);
	printf("PAGE_SHIFT = %d, %d\n", ulp_page_shift(), PAGE_SHIFT);
	return 0;
}

