// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

#include <elf/elf_api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>
#include <utils/task.h>


struct config config = {
	.log_level = -1,
};

enum command {
	CMD_NONE,
	CMD_PATCH,
} command_type = CMD_NONE;


static pid_t target_pid = -1;
static struct task *target_task = NULL;

enum {
	ARG_PATCH = 139,
	ARG_LOG_DEBUG,
	ARG_LOG_ERR,
};


static void print_help(void)
{
	printf(
	"\n"
	" Usage: upatch [OPTION]... [FILE]...\n"
	"\n"
	" User space patch\n"
	"\n"
	" Mandatory arguments to long options are mandatory for short options too.\n"
	"\n"
	" Option argument:\n"
	"\n"
	"  -p, --pid           specify a process identifier(pid_t)\n"
	"\n"
	" Operate argument:\n"
	"\n"
	"  --patch             patch a object file into target task\n"
	"\n"
	" Common argument:\n"
	"\n"
	"  -l, --log-level     set log level, default(%d)\n"
	"                      EMERG(%d),ALERT(%d),CRIT(%d),ERR(%d),WARN(%d)\n"
	"                      NOTICE(%d),INFO(%d),DEBUG(%d)\n"
	"  --log-debug         set log level to DEBUG(%d)\n"
	"  --log-error         set log level to ERR(%d)\n"
	"\n"
	"  -h, --help          display this help and exit\n"
	"  -v, --version       output version information and exit\n"
	"\n"
	" upatch %s\n",
	config.log_level,
	LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO,
	LOG_DEBUG,
	LOG_DEBUG,
	LOG_ERR,
	upatch_version()
	);
	exit(0);
}

static int parse_config(int argc, char *argv[])
{
	struct option options[] = {
		{ "pid",            required_argument, 0, 'p' },
		{ "patch",          no_argument,       0, ARG_PATCH },
		{ "version",        no_argument,       0, 'v' },
		{ "help",           no_argument,       0, 'h' },
		{ "log-level",      required_argument, 0, 'l' },
		{ "log-debug",      no_argument,       0, ARG_LOG_DEBUG },
		{ "log-error",      no_argument,       0, ARG_LOG_ERR },
		{ NULL }
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
		case ARG_PATCH:
			command_type = CMD_PATCH;
			break;
		case 'v':
			printf("version %s\n", upatch_version());
			exit(0);
		case 'h':
			print_help();
		case 'l':
			config.log_level = atoi(optarg);
			break;
		case ARG_LOG_DEBUG:
			config.log_level = LOG_DEBUG;
			break;
		case ARG_LOG_ERR:
			config.log_level = LOG_ERR;
			break;
		default:
			print_help();
		}
	}

	if (command_type == CMD_NONE) {
		fprintf(stderr, "Nothing to do, check -h, --help.\n");
		exit(1);
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

static void command_patch(void)
{
	fprintf(stdout, "TODO: finish me.\n");
	// TODO
}

int main(int argc, char *argv[])
{
	upatch_init();

	parse_config(argc, argv);

	set_log_level(config.log_level);

	target_task = open_task(target_pid, FTO_ALL);

	if (!target_task) {
		fprintf(stderr, "open %d failed. %s\n", target_pid, strerror(errno));
		return 1;
	}

	switch (command_type) {
	case CMD_PATCH:
		command_patch();
		break;
	case CMD_NONE:
	default:
		fprintf(stderr, "What to do.\n");
	}

	free_task(target_task);

	return 0;
}

