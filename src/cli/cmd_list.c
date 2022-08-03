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
#include <time.h>

#include <cli/cli_api.h>
#include <elf/elf_api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>

#include "cli-usdt.h"


static void cli_elf_list_handler(struct file_info *info)
{
	if (info->type != FILE_ELF)
		return;
	printf(" %s ELF %s %s\n",
		info->client_select?"> ":"  ",
		info->name,
		info->elf_build_id
	);
}

static void
cli_client_list_handler(struct nr_idx_bool *nib, struct client_info *info)
{
	char buffer[64];

	strftime(buffer, sizeof(buffer) - 1,
		"%m-%d-%Y/%T", localtime(&info->start.tv_sec));

	printf(" %s CLIENT %2d/%2d %-32s %2d\n",
		nib->is?"> ":"  ",
		nib->idx,
		nib->nr,
		buffer,
		info->connfd
	);
}

int cli_cmd_list(const struct cli_struct *cli, int argc, char *argv[])
{
	if (argc < 2) {
		printf("help LIST: to show help.\n");
	} else if (argc >= 2) {
		// LIST ELF
		if (strcasecmp(argv[1], "elf") == 0) {

			trace_cli_elf_list();

			return client_list_elf(cli->elf_client_fd, cli_elf_list_handler);

		// LIST CLIENT
		} else if (strcasecmp(argv[1], "client") == 0) {

			trace_cli_client_list();

			return client_list_client(cli->elf_client_fd,
					cli_client_list_handler);
		}
	}

	return -ENOENT;
}

