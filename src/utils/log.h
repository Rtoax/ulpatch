// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#pragma once

#include <syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ldebug(fmt...) _____log(LOG_DEBUG, __FILE__, __func__, __LINE__, fmt)
#define linfo(fmt...) _____log(LOG_INFO, __FILE__, __func__, __LINE__, fmt)
#define lnotice(fmt...) _____log(LOG_NOTICE, __FILE__, __func__, __LINE__, fmt)
#define lwarning(fmt...) _____log(LOG_WARNING, __FILE__, __func__, __LINE__,fmt)
#define lerror(fmt...) _____log(LOG_ERR, __FILE__, __func__, __LINE__, fmt)
#define lcrit(fmt...) _____log(LOG_CRIT, __FILE__, __func__, __LINE__, fmt)
#define lalert(fmt...) _____log(LOG_ALERT, __FILE__, __func__, __LINE__, fmt)
#define lemerg(fmt...) _____log(LOG_EMERG, __FILE__, __func__, __LINE__, fmt)

int
_____log(int level, const char *file, const char *func,
	unsigned long int line, char *fmt, ...);

void set_log_level(int level);

#ifdef __cplusplus
}
#endif

