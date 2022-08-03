// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#include <cli/cli_api.h>
#include <elf/elf_api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>

#include "cli-usdt.h"


static int test_server_handler(const char *s, int slen)
{
	ldebug("handle: %s\n", s);
	return 0;
}

int cli_cmd_test(const struct cli_struct *cli, int argc, char *argv[])
{
	if (argc < 2) {
		printf("help TEST: to show help.\n");
	} else if (argc >= 2) {
		// TEST SERVER
		if (strcasecmp(argv[1], "server") == 0) {
			return client_test_server(cli->elf_client_fd,
						test_server_handler);
		}
	}
	return -ENOENT;
}

