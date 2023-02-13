// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao */
#include <stdio.h>

#include "util.h"
#include "compiler.h"


static const char __unused *color[] = {
	"\033[48;5;255m",
	"\033[48;5;252m",
	"\033[48;5;250m",
	"\033[48;5;248m",
	"\033[48;5;246m",
	"\033[48;5;244m",
	"\033[48;5;242m",
	"\033[48;5;240m",
	"\033[48;5;238m",
	"\033[48;5;236m",
	"\033[48;5;234m",
	"\033[48;5;232m",
};


const char *upatch_arch(void)
{
#if defined(__x86_64__)
	return "x86_64";
#elif defined(__aarch64__)
	return "aarch64";
#else
	return "Unsupport";
#endif
}

const char *upatch_version(void)
{
#if !defined(UPATCH_VERSION)
# error "Must define string UPATCH_VERSION"
#endif
#if 0
	int i;

	for (i = 0; i < ARRAY_SIZE(color); i++) {
		printf("%s  %s", color[i], "\033[m");
	}
	printf("\n");
#endif
	return UPATCH_VERSION;
}

