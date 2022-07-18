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


int cli_cmd_delete(const struct cli_struct *cli, int argc, char *argv[])
{
	if (argc < 2) {
		printf("help DELETE: to show help.\n");
	} else if (argc >= 2) {
		// DELETE ELF
		if (strcasecmp(argv[1], "elf") == 0) {
			if (argc < 3) {
				printf("help DELETE ELF: to show help.\n");
				return -ENOEXEC; /* Exec format error */
			}
			char *filepath = argv[2];

			if (access(filepath, F_OK) != 0) {
				fprintf(stderr, "%s not exist.\n", filepath);
				return -ENOENT;
			}

			trace_cli_elf_delete(filepath);

			return client_delete_elf_file(cli->elf_client_fd, filepath);
		}
	}

	return -ENOENT;
}

