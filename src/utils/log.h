// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#pragma once

#include <stdio.h>
#include <syslog.h>
#include <stdbool.h>

#include "utils/compiler.h"

/* Has prefix if set_log_prefix on */
#define ulp_debug(fmt...) ulp_log(LOG_DEBUG, true, __FILE__, __func__, __LINE__, fmt)
#define ulp_info(fmt...) ulp_log(LOG_INFO, true, __FILE__, __func__, __LINE__, fmt)
#define ulp_notice(fmt...) ulp_log(LOG_NOTICE, true, __FILE__, __func__, __LINE__, fmt)
#define ulp_warning(fmt...) ulp_log(LOG_WARNING, true, __FILE__, __func__, __LINE__, fmt)
#define ulp_error(fmt...) ulp_log(LOG_ERR, true, __FILE__, __func__, __LINE__, fmt)
#define ulp_crit(fmt...) ulp_log(LOG_CRIT, true, __FILE__, __func__, __LINE__, fmt)
#define ulp_alert(fmt...) ulp_log(LOG_ALERT, true, __FILE__, __func__, __LINE__, fmt)
#define ulp_emerg(fmt...) ulp_log(LOG_EMERG, true, __FILE__, __func__, __LINE__, fmt)


__printf(6, 7)
int ulp_log(int level, bool has_prefix, const char *file, const char *func,
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

int memshowinlog(int level, const void *data, int data_len);
