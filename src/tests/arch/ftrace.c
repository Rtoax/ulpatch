// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <utils/disasm.h>
#include <utils/log.h>
#include <utils/list.h>
#include <task/task.h>
#include <tests/test-api.h>

TEST_STUB(arch_ftrace);

#if defined(__x86_64__)
TEST(Arch_ftrace, ftrace_call_replace, 0)
{
	char expect[] = {0xe8, 0xff, 0xff, 0xff, 0xff};
	union text_poke_insn insn;

	/* new = e8 ff ff ff ff */
	const char *new = ftrace_call_replace(&insn, -4, 0);

	memshowinlog(LOG_INFO, new, sizeof(insn));
	fdisasm_arch(stdout, "ftrace", 0, (void *)new, sizeof(insn));

	return memcmp((void *)new, expect, sizeof(insn));
}
#endif

