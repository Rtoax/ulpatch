// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <stdarg.h>
#include <libgen.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <utils/log.h>

#include "compiler.h"
#include "util.h"


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
static bool prefix_on = true;
static FILE *log_fp = NULL;


void set_log_level(int level)
{
	log_level = level;
}

int get_log_level(void)
{
	return log_level;
}

void set_log_debug(void)
{
	set_log_level(LOG_DEBUG);
}
void set_log_error(void)
{
	set_log_level(LOG_ERR);
}

void set_log_prefix(bool on)
{
	prefix_on = !!on;
}

void set_log_fp(FILE *fp)
{
	log_fp = fp;
}

FILE *get_log_fp(void)
{
	if (!log_fp)
		set_log_fp(stdout);
	return log_fp;
}

#define INNER_FPRINTF(fp, fmt...) ({ \
	int ____n; \
	____n = fprintf(fp, fmt); \
	if (level <= LOG_ERR) { \
		fprintf(stderr, fmt); \
	} \
	____n; \
})

#define INNER_VFPRINTF(fp, fmt, va) ({ \
	int ____n; \
	va_list ____va; \
	____n = vfprintf(fp, fmt, va); \
	if (level <= LOG_ERR) { \
		va_start(____va, fmt); \
		vfprintf(stderr, fmt, ____va); \
		va_end(____va); \
	} \
	____n; \
})

int _____log(int level, const char *file, const char *func,
		unsigned long int line, char *fmt, ...)
{
	int n = 0;
	FILE *fp = get_log_fp();
	va_list va;
	int _en = errno;

	if (level > log_level)
		return 0;

	if (likely(prefix_on)) {
		char buffer[32];
		time_t timestamp = time(NULL);

		/* like 15:53:52 */
		strftime(buffer, 32, "%T", localtime(&timestamp));

		INNER_FPRINTF(fp, "%s %s[%s %s:%ld]",
			buffer,
			level_prefix[level],
			basename((char *)file),
			func,
			line);
		if (level <= LOG_ERR && _en != 0)
			INNER_FPRINTF(fp, "[%s]", strerror(_en));

		INNER_FPRINTF(fp, " ");
	}

	va_start(va, fmt);
	n += INNER_VFPRINTF(fp, fmt, va);
	va_end(va);

	return n;
}

int memshowinlog(int level, const void *data, int data_len)
{
	if (level > log_level)
		return 0;
	return memshow(get_log_fp(), data, data_len);
}

