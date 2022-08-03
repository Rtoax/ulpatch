// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdarg.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <utils/log.h>

static const char *level_prefix[] = {
	"[\033[1;5;31mEMERG\033[m]",
	"[\033[1;5;31mALERT\033[m]",
	"[\033[1;31m CRIT\033[m]",
	"[\033[1;31mERROR\033[m]",
	"[\033[1;32m WARN\033[m]",
	"[\033[1;33mNOTIC\033[m]",
	"[\033[1;34m INFO\033[m]",
	"[\033[1;35mDEBUG\033[m]",
};

static int log_level = LOG_DEBUG;

void set_log_level(int level)
{
	log_level = level;
}

int _____log(int level, const char *file, const char *func,
		unsigned long int line, char *fmt, ...)
{
	int n = 0;
	FILE *fp = stdout;
	va_list va;

	if (level > log_level)
		return 0;

	char buffer[32];
	time_t timestamp = time(NULL);

	// like 15:53:52
	strftime(buffer, 32, "%T", localtime(&timestamp));

	va_start(va, fmt);

	fprintf(fp, "%s %s[%s:%ld] ", buffer, level_prefix[level], func, line);
	n += vfprintf(fp, fmt, va);

	va_end(va);

	return n;
}

