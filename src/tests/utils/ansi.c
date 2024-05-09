// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/ansi.h>
#include <elf/elf_api.h>

#include "../test_api.h"


TEST(UtilsAnsi,	base,	0)
{
	int i;

	if (ansi_gray_num() != 24)
		return -1;

	for (i = 0; i < ansi_gray_num(); i++)
		printf("%sX%s", ansi_gray(i), ANSI_RESET);
	printf("\n");

	return 0;
}

