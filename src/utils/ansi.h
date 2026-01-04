// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#pragma once

/* Clear screen */
#define ANSI_CLR	"\033[2J"

#define ANSI_RED	"\033[31m"
#define ANSI_GREEN	"\033[32m"
#define ANSI_YELLOW	"\033[33m"
#define ANSI_BLUE	"\033[34m"

#define ANSI_BOLD	"\033[1m"
#define ANSI_GRAY	"\033[2m"
#define ANSI_ITALIC	"\033[3m"
#define ANSI_UNDERLINE	"\033[4m"
#define ANSI_SHINE	"\033[5m"
#define ANSI_REVERSE	"\033[7m"

#define ANSI_CMD	"\033[1;3m"
#define ANSI_WARNING	"\033[1;31m"
#define ANSI_SUCCESS	"\033[1;32m"
#define ANSI_FAILED	"\033[1;31m"

#define ANSI_RESET	"\033[m"


int ansi_gray_num(void);
const char *ansi_gray(int idx);

int fpansi_clr(FILE *fp);
int fpansi_red(FILE *fp);
int fpansi_green(FILE *fp);
int fpansi_yellow(FILE *fp);
int fpansi_blue(FILE *fp);
int fpansi_bold(FILE *fp);
int fpansi_gray(FILE *fp);
int fpansi_italic(FILE *fp);
int fpansi_underline(FILE *fp);
int fpansi_shine(FILE *fp);
int fpansi_reverse(FILE *fp);
int fpansi_reset(FILE *fp);
