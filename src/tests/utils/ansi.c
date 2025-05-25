// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include "utils/log.h"
#include "utils/list.h"
#include "utils/util.h"
#include "utils/ansi.h"
#include "elf/elf-api.h"
#include "tests/test-api.h"


TEST(Utils_ansi, base, 0)
{
	int i;

	if (ansi_gray_num() != 24)
		return -1;

	for (i = 0; i < ansi_gray_num(); i++)
		printf("%sX%s", ansi_gray(i), ANSI_RESET);
	printf("\n");

	fpansi_clr(stdout);
	fpansi_red(stdout);
	fpansi_green(stdout);
	fpansi_yellow(stdout);
	fpansi_blue(stdout);
	fpansi_bold(stdout);
	fpansi_gray(stdout);
	fpansi_italic(stdout);
	fpansi_underline(stdout);
	fpansi_shine(stdout);
	fpansi_reverse(stdout);
	fpansi_reset(stdout);

	return 0;
}
