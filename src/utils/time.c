// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#include <time.h>
#include <sys/time.h>

#include "utils/time.h"


unsigned long secs(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec + tv.tv_usec / 1000000UL;
}

unsigned long usecs(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000UL + tv.tv_usec;
}
