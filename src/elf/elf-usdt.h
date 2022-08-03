// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <string.h>

#include <utils/util.h>
#include <utils/trace.h>


#define trace_elf_handle_msg_start(cmd_code) \
	__trace_cli_probe_i1(elf, handle_msg_start, cmd_code)

#define trace_elf_handle_msg_end(cmd_code) \
	__trace_cli_probe_i1(elf, handle_msg_end, cmd_code)

