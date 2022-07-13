#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_LINENOISE
#include <linenoise.h>
#else
#include <utils/linenoise.h>
#endif

#include <cli/cli_api.h>
#include <elf/elf_api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>


static int cli_handle_command(int argc, char *argv[])
{
	char *command = argv[0];

	// LOAD
	if (strcasecmp(command, "load") == 0) {
		return cli_cmd_load(&cli, argc, argv);
	// DELETE
	} else if (strcasecmp(argv[0], "delete") == 0) {
		return cli_cmd_delete(&cli, argc, argv);
	// LIST
	} else if (strcasecmp(argv[0], "list") == 0) {
		return cli_cmd_list(&cli, argc, argv);
	// SELECT
	} else if (strcasecmp(argv[0], "select") == 0) {
		return cli_cmd_select(&cli, argc, argv);
	// GET
	} else if (strcasecmp(argv[0], "get") == 0) {
		return cli_cmd_get(&cli, argc, argv);
	// TEST
	} else if (strcasecmp(argv[0], "test") == 0) {
		return cli_cmd_test(&cli, argc, argv);
	// SHELL <command> args
	} else if (strcasecmp(argv[0], "shell") == 0) {
		return cli_cmd_shell(argc, argv);
	} else {
		fprintf(stderr, "Unknown command: %s\n", argv[0]);
		return -ENOENT;
	}

	return -ENOENT;
}

int cli_send_command(int argc, char *argv[])
{
#if 0
	int i;
	for (i = 0; i < argc; i++) {
		ldebug("argv[%d] = %s\n", i, argv[i]);
	}
#endif
	return cli_handle_command(argc, argv);
}
