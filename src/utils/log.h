// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#pragma once

#include <stdio.h>
#include <syslog.h>
#include <stdbool.h>

/* Has prefix if set_log_prefix on */
#define ldebug(fmt...) ulp_log(LOG_DEBUG, true, __FILE__, __func__, __LINE__, fmt)
#define linfo(fmt...) ulp_log(LOG_INFO, true, __FILE__, __func__, __LINE__, fmt)
#define lnotice(fmt...) ulp_log(LOG_NOTICE, true, __FILE__, __func__, __LINE__, fmt)
#define lwarning(fmt...) ulp_log(LOG_WARNING, true, __FILE__, __func__, __LINE__, fmt)
#define lerror(fmt...) ulp_log(LOG_ERR, true, __FILE__, __func__, __LINE__, fmt)
#define lcrit(fmt...) ulp_log(LOG_CRIT, true, __FILE__, __func__, __LINE__, fmt)
#define lalert(fmt...) ulp_log(LOG_ALERT, true, __FILE__, __func__, __LINE__, fmt)
#define lemerg(fmt...) ulp_log(LOG_EMERG, true, __FILE__, __func__, __LINE__, fmt)


int __attribute__((format(printf, 6, 7)))
ulp_log(int level, bool has_prefix, const char *file, const char *func,
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

