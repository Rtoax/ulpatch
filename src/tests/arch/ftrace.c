// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/task.h>
#include <tests/test_api.h>


#if defined(__x86_64__)
TEST(Arch_ftrace, ftrace_call_replace, 0)
{
	char expect[] = {0xe8, 0xff, 0xff, 0xff, 0xff};
	union text_poke_insn insn;

	// new = e8 ff ff ff ff
	const char *new = ftrace_call_replace(&insn, -4, 0);

	memshowinlog(LOG_INFO, new, sizeof(insn));

	return memcmp((void *)new, expect, sizeof(insn));
}
#endif

