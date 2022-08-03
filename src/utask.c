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
#include <utils/task.h>
#include <utils/compiler.h>


struct config config = {
	.log_level = LOG_DEBUG,
};

static pid_t target_pid = -1;


static void print_help(void)
{
	printf(
	"\n"
	" Usage: utask [OPTION]... [FILE]...\n"
	"\n"
	" User space task\n"
	"\n"
	" Mandatory arguments to long options are mandatory for short options too.\n"
	"\n"
	" Essential argument:\n"
	"\n"
	"  -p, --pid           specify a process identifier(pid_t)\n"
	"\n"
	" Other argument:\n"
	"\n"
	"  -l, --log-level     set log level, default(%d)\n"
	"                      EMERG(%d),ALERT(%d),CRIT(%d),ERR(%d),WARN(%d)\n"
	"                      NOTICE(%d),INFO(%d),DEBUG(%d)\n"
	"  -h, --help          display this help and exit\n"
	"  -v, --version       output version information and exit\n"
	"\n"
	" utask %s\n",
	config.log_level,
	LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO,
	LOG_DEBUG,
	elftools_version()
	);
	exit(0);
}

static int parse_config(int argc, char *argv[])
{
	struct option options[] = {
		{"pid",		required_argument,	0,	'p'},
		{"version",	no_argument,	0,	'v'},
		{"help",	no_argument,	0,	'h'},
		{"log-level",		required_argument,	0,	'l'},
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "p:vhl:", options, &option_index);
		if (c < 0) {
			break;
		}
		switch (c) {
		case 'p':
			target_pid = atoi(optarg);
			break;
		case 'v':
			printf("version %s\n", elftools_version());
			exit(0);
		case 'h':
			print_help();
		case 'l':
			config.log_level = atoi(optarg);
			break;
		default:
			print_help();
		}
	}

	if (target_pid == -1) {
		fprintf(stderr, "Specify pid with -p, --pid.\n");
		exit(1);
	}

	if (!proc_pid_exist(target_pid)) {
		fprintf(stderr, "pid %d not exist.\n", target_pid);
		exit(1);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	parse_config(argc, argv);

	return 0;
}

