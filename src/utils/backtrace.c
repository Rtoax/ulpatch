// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdio.h>
#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include <utils/log.h>
#include <utils/util.h>


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

