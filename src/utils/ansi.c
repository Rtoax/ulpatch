// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <stdio.h>
#include <stdlib.h>

#include "compiler.h"
#include "util.h"

static const char *ANSI_COLORS_GRAY[] = {
	"\033[48;5;255m",
	"\033[48;5;254m",
	"\033[48;5;253m",
	"\033[48;5;252m",
	"\033[48;5;251m",
	"\033[48;5;250m",
	"\033[48;5;249m",
	"\033[48;5;248m",
	"\033[48;5;247m",
	"\033[48;5;246m",
	"\033[48;5;245m",
	"\033[48;5;244m",
	"\033[48;5;243m",
	"\033[48;5;242m",
	"\033[48;5;241m",
	"\033[48;5;240m",
	"\033[48;5;239m",
	"\033[48;5;238m",
	"\033[48;5;237m",
	"\033[48;5;236m",
	"\033[48;5;235m",
	"\033[48;5;234m",
	"\033[48;5;233m",
	"\033[48;5;232m",
};

int ansi_gray_num(void)
{
	return ARRAY_SIZE(ANSI_COLORS_GRAY);
}

const char *ansi_gray(int idx)
{
	if (idx < 0 || idx >= ansi_gray_num())
		return "";
	return ANSI_COLORS_GRAY[idx];
}

