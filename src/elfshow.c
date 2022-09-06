// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#include <elf/elf_api.h>
#include <cli/cli_api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>


// node: struct str_node.node
static LIST_HEAD(pre_load_files);
static char *selected_elf = NULL;

struct config config = {
	.log_level = LOG_DEBUG,
	.role = -1,	// server or client
	.mode = -1,	// test, cli, gtk, sleep ...
	.daemon = false,
};


static void load_pre_list_elf(void)
{
	struct str_node *file = NULL, *tmp;

	int tmp_client_fd = create_elf_client();

	strstr_for_each_node_safe(file, tmp, &pre_load_files) {
		// Must exist
		if (access(file->str, F_OK) != 0) {
			fprintf(stderr, "%s not exist.\n", file->str);
			continue;
		}
		ldebug("name = %s\n", file->str);
		client_open_elf_file(tmp_client_fd, file->str);
	}

	close_elf_client(tmp_client_fd);
}

static void print_help(void)
{
	printf(
	"\n"
	" Usage: elfshow [OPTION]... [FILE]...\n"
	"\n"
	" ELF Show\n"
	"\n"
	" Mandatory arguments to long options are mandatory for short options too.\n"
	"\n"
	" Server specific:\n"
	"\n"
	"  -s, --server        run in server mode, listen on \"%s\"\n"
	"\n"
	" Client specific:\n"
	"\n"
	"  -c, --client        run in client mode, connecting to <server>\n"
	"  -e, --select-elf    select one elf that pre load(-i, --input-files)\n"
	"\n"
	" Server or Client:\n"
	"\n"
	"  -i, --input-files   input files to pre-load, auto filter out non exist\n"
	"                      files.\n"
	"                      for example: -i /bin/ls,/bin/cat,elfshow,\n"
	"\n"
	"  -l, --log-level     set log level, default(%d)\n"
	"                      EMERG(%d),ALERT(%d),CRIT(%d),ERR(%d),WARN(%d)\n"
	"                      NOTICE(%d),INFO(%d),DEBUG(%d)\n"
	"  -m, --mode          set execute mode, default(%d)\n"
	"                      SLEEP(%d),CLI(%d),GTK(%d)\n"
	"  -d, --daemon        run in background\n"
	"                      if server, --mode will set to SLEEP\n"
	"  -h, --help          display this help and exit\n"
	"  -v, --version       output version information and exit\n"
	"\n"
	" elfshow %s\n",
	ELF_UNIX_PATH,
	config.log_level,
	LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO,
	LOG_DEBUG,
	config.mode,
	MODE_SLEEP, MODE_CLI, MODE_GTK,
	upatch_version()
	);
	exit(0);
}

static int parse_config(int argc, char *argv[])
{
	struct option options[] = {
		{"version",	no_argument,	0,	'v'},
		{"help",	no_argument,	0,	'h'},
		{"server",	no_argument,	0,	's'},
		{"client",	no_argument,	0,	'c'},
		{"daemon",	no_argument,	0,	'd'},
		{"select-elf",	required_argument,	0,	'e'},
		{"input-files",		required_argument,	0,	'i'},
		{"log-level",		required_argument,	0,	'l'},
		{"mode",		required_argument,	0,	'm'},
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "vhl:m:sce:di:", options, &option_index);
		if (c < 0) {
			break;
		}
		switch (c) {
		case 'v':
			printf("version %s\n", upatch_version());
			exit(0);
		case 'h':
			print_help();
		case 'l':
			config.log_level = atoi(optarg);
			break;
		case 'm':
			config.mode = atoi(optarg);
			break;
		case 's':
			config.role = ROLE_SERVER;
			break;
		case 'c':
			config.role = ROLE_CLIENT;
			break;
		case 'd':
			config.daemon = true;
			break;
		case 'i':
			parse_strstr((char *)optarg, &pre_load_files);
			break;
		case 'e':
			selected_elf = (char *)optarg;
			break;
		default:
			print_help();
			break;
		}
	}

	/* Set log level */
	set_log_level(config.log_level);

	/* Check daemon */
	if (config.daemon) {
		switch (config.role) {
		case ROLE_SERVER:
			config.mode = MODE_SLEEP;
			break;
		case ROLE_CLIENT:
			if ((config.mode == MODE_CLI)) {
			fprintf(stderr, "client: cli(-m %d) conflict with daemon(-d).\n",
				config.mode);
			exit(1);
			}
		}
	}

	/* Server or Client */
	switch (config.role) {
	case ROLE_SERVER:
		break;
	case ROLE_CLIENT:
		if (config.mode == MODE_SLEEP) {
			fprintf(stderr,
				"client(-c) not support sleep(%d) mode(-m).\n"
				"Try '--help' for more information.\n",
				MODE_SLEEP);
			exit(1);
		}
		break;
	default:
		fprintf(stderr, "wrong role(%d, -s, --server or -c, --client).\n"
			"Try '--help' for more information.\n",
			config.role);
		exit(1);
	}

	/* Check mode */
	switch (config.mode) {
	case MODE_SLEEP ... MODE_GTK:
		break;
	default:
		fprintf(stderr, "wrong mode(%d, -m), check with -h, --help.\n"
			"Try '--help' for more information.\n",
			config.mode);
		exit(1);
	}

	/* Select one elf check */
	if (selected_elf) {
		bool found = false;
		struct str_node *file = NULL, *tmp;

		list_for_each_entry_safe(file, tmp, &pre_load_files, node) {
			if (!strcmp(selected_elf, file->str)) {
				ldebug("Find %s in `-i`.\n", selected_elf);
				found = true;
				break;
			}
		}
		if (!found) {
			fprintf(stderr, "%s not in `-i, --input-files' list.\n",
				selected_elf);
			exit(1);
		}
	}

	return 0;
}

int cli_selected_elf_cb(void *arg)
{
	int ret = 0;

	if (selected_elf) {
		ret = client_select_elf_file(cli.elf_client_fd, selected_elf);
	}

	return ret;
}

int main(int argc, char *argv[])
{
	upatch_init();

	parse_config(argc, argv);

	/* Run background */
	if (config.daemon) daemonize();

	/* Server or Client */
	switch (config.role) {
	case ROLE_SERVER:
		if(elf_main(argc, argv) != 0) {
			goto failed;
		}
		break;
	case ROLE_CLIENT:
		break;
	}

	load_pre_list_elf();
	cli_register_pre_command_cb(cli_selected_elf_cb, NULL);

	/* Run mode */
	switch (config.mode) {
	case MODE_CLI:
		cli_main(argc, argv);
		// if select one
		break;
	case MODE_GTK:
		break;
	case MODE_SLEEP:
		while (1) sleep(10);
		break;
	}

	return 0;

failed:
	return -1;
}

