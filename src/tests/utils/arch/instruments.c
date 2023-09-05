// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>
#include <unistd.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/task.h>

#include "../../test_api.h"

#if defined(__x86_64__)
TEST(Insn,	text_opcode_size,	0)
{
	if (text_opcode_size(INST_INT3) != INT3_INSN_SIZE)
		return -1;
	if (text_opcode_size(INST_RET) != RET_INSN_SIZE)
		return -1;
	if (text_opcode_size(INST_CALL) != CALL_INSN_SIZE)
		return -1;
	if (text_opcode_size(INST_JMP32) != JMP32_INSN_SIZE)
		return -1;
	if (text_opcode_size(INST_JMP8) != JMP8_INSN_SIZE)
		return -1;

	return 0;
}
#endif

