// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#include <stdio.h>
#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include "utils/log.h"
#include "utils/backtrace.h"

#if !defined(CONFIG_LIBUNWIND)
# error "No CONFIG_LIBUNWIND found"
#endif

int do_backtrace(FILE *fp)
{
	unw_cursor_t cursor;
	unw_context_t context;
	unw_word_t offset, pc;
	char fname[64];

	unw_getcontext(&context);
	unw_init_local(&cursor, &context);

	if (!fp)
		fp = stdout;

	while (unw_step(&cursor) > 0) {
		unw_get_reg(&cursor, UNW_REG_IP, &pc);
		fname[0] = '\0';
		unw_get_proc_name(&cursor, fname, sizeof(fname), &offset);
		fprintf(fp, "0x%lx : (%s+0x%lx) [0x%lx]\n", pc, fname, offset,
			pc);
	}
	return 0;
}

const char *libunwind_version(void)
{
	static bool init = false;
	static char buf[64];
	if (!init) {
		snprintf(buf, sizeof(buf), "%d.%d.%d", UNW_VERSION_MAJOR,
			UNW_VERSION_MINOR, UNW_VERSION_EXTRA);
		init = true;
	}
	return buf;
}
