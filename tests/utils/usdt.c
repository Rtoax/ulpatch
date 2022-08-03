// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <errno.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <elf/elf_api.h>

#include <cli/cli-usdt.h>

#include "../test_api.h"


TEST(usdt,	cli,	0)
{
	trace_cli_elf_load("/usr/bin/ls");
	trace_cli_elf_delete("/usr/bin/ls");
	trace_cli_elf_select("/usr/bin/ls");
	trace_cli_elf_list();
	trace_cli_shell("ls");

	return 0;
}

#include <elf/elf-usdt.h>

TEST(usdt,	elf,	0)
{
	trace_elf_handle_msg_start(CMD_ELF_LOAD);
	trace_elf_handle_msg_end(CMD_ELF_LOAD);

	return 0;
}
