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


static void cli_elf_list_handler(struct file_info *info)
{
	if (info->type == FILE_ELF)
		printf(" %s ELF %s\n", info->client_select?"> ":"  ", info->name);
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
		}
	}

	return -ENOENT;
}
