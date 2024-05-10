// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <stdio.h>
#include <stdlib.h>

#include <utils/ansi.h>
#include <utils/compiler.h>
#include <utils/util.h>

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

int fpansi_clr(FILE *fp)
{
	return fprintf(fp, ANSI_CLR);
}

int fpansi_red(FILE *fp)
{
	return fprintf(fp, ANSI_RED);
}

int fpansi_green(FILE *fp)
{
	return fprintf(fp, ANSI_GREEN);
}

int fpansi_yellow(FILE *fp)
{
	return fprintf(fp, ANSI_YELLOW);
}

int fpansi_blue(FILE *fp)
{
	return fprintf(fp, ANSI_BLUE);
}

int fpansi_bold(FILE *fp)
{
	return fprintf(fp, ANSI_BOLD);
}

int fpansi_gray(FILE *fp)
{
	return fprintf(fp, ANSI_GRAY);
}

int fpansi_italic(FILE *fp)
{
	return fprintf(fp, ANSI_ITALIC);
}

int fpansi_underline(FILE *fp)
{
	return fprintf(fp, ANSI_UNDERLINE);
}

int fpansi_shine(FILE *fp)
{
	return fprintf(fp, ANSI_SHINE);
}

int fpansi_reverse(FILE *fp)
{
	return fprintf(fp, ANSI_REVERSE);
}

int fpansi_reset(FILE *fp)
{
	return fprintf(fp, ANSI_RESET);
}

