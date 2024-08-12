// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#pragma once

#include <stdio.h>
#include <syslog.h>
#include <stdbool.h>

/* Has prefix if set_log_prefix on */
#define ldebug(fmt...) _____log(LOG_DEBUG, true, __FILE__, __func__, __LINE__, fmt)
#define linfo(fmt...) _____log(LOG_INFO, true, __FILE__, __func__, __LINE__, fmt)
#define lnotice(fmt...) _____log(LOG_NOTICE, true, __FILE__, __func__, __LINE__, fmt)
#define lwarning(fmt...) _____log(LOG_WARNING, true, __FILE__, __func__, __LINE__, fmt)
#define lerror(fmt...) _____log(LOG_ERR, true, __FILE__, __func__, __LINE__, fmt)
#define lcrit(fmt...) _____log(LOG_CRIT, true, __FILE__, __func__, __LINE__, fmt)
#define lalert(fmt...) _____log(LOG_ALERT, true, __FILE__, __func__, __LINE__, fmt)
#define lemerg(fmt...) _____log(LOG_EMERG, true, __FILE__, __func__, __LINE__, fmt)

/* No prefix in any way */
#define debug(fmt...) _____log(LOG_DEBUG, false, __FILE__, __func__, __LINE__, fmt)
#define info(fmt...) _____log(LOG_INFO, false, __FILE__, __func__, __LINE__, fmt)
#define notice(fmt...) _____log(LOG_NOTICE, false, __FILE__, __func__, __LINE__, fmt)
#define warning(fmt...) _____log(LOG_WARNING, false, __FILE__, __func__, __LINE__, fmt)
#define error(fmt...) _____log(LOG_ERR, false, __FILE__, __func__, __LINE__, fmt)
#define crit(fmt...) _____log(LOG_CRIT, false, __FILE__, __func__, __LINE__, fmt)
#define alert(fmt...) _____log(LOG_ALERT, false, __FILE__, __func__, __LINE__, fmt)
#define emerg(fmt...) _____log(LOG_EMERG, false, __FILE__, __func__, __LINE__, fmt)

int __attribute__((format(printf, 6, 7)))
_____log(int level, bool has_prefix, const char *file, const char *func,
	 unsigned long int line, char *fmt, ...);

void set_log_fp(FILE *fp);
FILE *get_log_fp(void);
int get_log_level(void);
void set_log_level(int level);
void set_log_debug(void);
void set_log_error(void);
void set_log_prefix(bool on);

int str2loglevel(const char *str);
const char *log_level_list(void);

