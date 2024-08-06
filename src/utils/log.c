// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <stdarg.h>
#include <libgen.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <utils/log.h>

#include <utils/compiler.h>
#include <utils/util.h>


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

static int log_level = LOG_ERR;
static bool prefix_on = false;
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

int str2loglevel(const char *str)
{
	if (!str)
		return LOG_EMERG;

	if (!strcasecmp(str, "debug") || !strcasecmp(str, "dbg"))
		return LOG_DEBUG;
	else if (!strcasecmp(str, "info") || !strcasecmp(str, "inf"))
		return LOG_INFO;
	else if (!strcasecmp(str, "notice") || !strcasecmp(str, "note"))
		return LOG_NOTICE;
	else if (!strcasecmp(str, "warning") || !strcasecmp(str, "warn"))
		return LOG_WARNING;
	else if (!strcasecmp(str, "error") || !strcasecmp(str, "err"))
		return LOG_ERR;
	else if (!strcasecmp(str, "crit"))
		return LOG_CRIT;
	else if (!strcasecmp(str, "alert"))
		return LOG_ALERT;
	else if (!strcasecmp(str, "emerg"))
		return LOG_EMERG;
	else {
		fprintf(stderr, "Unknown log level string %s\n", str);
		return LOG_EMERG;
	}
}

const char *log_level_list(void)
{
	return "debug,dbg,info,inf,notice,note,warning,warn,error,err,crit,alert,emerg";
}

int __attribute__((format(printf, 6, 7)))
_____log(int level, bool has_prefix, const char *file, const char *func,
	 unsigned long int line, char *fmt, ...)
{
	int n = 0;
	FILE *fp = get_log_fp();
	va_list va;
	int _en = errno;
	static bool syslog_init = false;

	if (unlikely(!syslog_init)) {
		setlogmask(LOG_UPTO(LOG_ERR));
		openlog("ulpatch", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
		syslog_init = true;
	}

	/* syslog anyway */
	va_start(va, fmt);
	vsyslog(level, fmt, va);
	va_end(va);

	if (level > log_level)
		return 0;

	if (has_prefix && likely(prefix_on)) {
		char buffer[32];
		time_t timestamp = time(NULL);

		/* like 15:53:52 */
		strftime(buffer, 32, "%T", localtime(&timestamp));

		fprintf(fp, "%s %s[%s %s:%ld]",
			buffer,
			level_prefix[level],
			basename((char *)file),
			func,
			line);
		if (level <= LOG_ERR && _en != 0)
			fprintf(fp, "[%s]", strerror(_en));

		fprintf(fp, " ");
	}

	va_start(va, fmt);
	n += vfprintf(fp, fmt, va);
	va_end(va);

	return n;
}

int memshowinlog(int level, const void *data, int data_len)
{
	if (level > log_level)
		return 0;
	return memshow(get_log_fp(), data, data_len);
}

