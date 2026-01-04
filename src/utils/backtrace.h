// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#pragma once

#if defined(CONFIG_LIBUNWIND) && defined(CONFIG_LIBUNWIND)
int do_backtrace(FILE *fp);
const char *libunwind_version(void);
#else
# define do_backtrace(fp) ({-1;})
# define libunwind_version()	"Not support libunwind"
#endif
