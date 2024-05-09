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

	pansi_clr(stdout);
	pansi_red(stdout);
	pansi_green(stdout);
	pansi_yellow(stdout);
	pansi_blue(stdout);
	pansi_bold(stdout);
	pansi_gray(stdout);
	pansi_italic(stdout);
	pansi_underline(stdout);
	pansi_shine(stdout);
	pansi_reverse(stdout);
	pansi_reset(stdout);

	return 0;
}

