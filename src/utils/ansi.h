// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
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

