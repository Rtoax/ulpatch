// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <sys/types.h>
#include <unistd.h>
#include <utils/log.h>
#include <utils/util.h>
#include <utils/list.h>
#include <tests/test-api.h>


TEST(Utils, page, 0)
{
	int ret = 0;

	printf("PAGE_SIZE = %x, %lx\n", ulp_page_size(), PAGE_SIZE);
	printf("PAGE_SHIFT = %d, %d\n", ulp_page_shift(), PAGE_SHIFT);

	ret += ulp_page_size() != PAGE_SIZE;
	ret += ulp_page_shift() != PAGE_SHIFT;

	return ret;
}
