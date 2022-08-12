// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <cli/cli_api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>
#include <utils/task.h>


struct config config = {
	.log_level = -1,
};

static pid_t target_pid = -1;
static struct task *target_task = NULL;

static const char *patch_object_file = NULL;

/* This is ftrace object file path, during 'make install' install to
 * /usr/share/elftools/, this macro is a absolute path of LSB relocatable file.
 *
 * see top level of CMakeLists.txt
 */
#if !defined(ELFTOOLS_FTRACE_OBJ_PATH)
# error "Need ELFTOOLS_FTRACE_OBJ_PATH"
#endif


static void print_help(void)
{
	printf(
	"\n"
	" Usage: uftrace [OPTION]... [FILE]...\n"
	"\n"
	" User space ftrace\n"
	"\n"
	" Mandatory arguments to long options are mandatory for short options too.\n"
	"\n"
	" Base argument:\n"
	"\n"
	"  -p, --pid           specify a process identifier(pid_t)\n"
	"\n"
	"\n"
	" Ftrace argument:\n"
	"\n"
	"  -j, --patch-obj     input a ELF 64-bit LSB relocatable object file.\n"
	"                      actually, this input is not necessary, but you know\n"
	"                      how to generate a ftrace relocatable object.\n"
	"                      default: %s\n"
	"\n"
	"\n"
	" Common argument:\n"
	"\n"
	"  -l, --log-level     set log level, default(%d)\n"
	"                      EMERG(%d),ALERT(%d),CRIT(%d),ERR(%d),WARN(%d)\n"
	"\n"
	"                      NOTICE(%d),INFO(%d),DEBUG(%d)\n"
	"  -h, --help          display this help and exit\n"
	"  -v, --version       output version information and exit\n"
	"\n"
	" uftrace %s\n",
	ELFTOOLS_FTRACE_OBJ_PATH,
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
		{"patch-obj",		required_argument,	0,	'j'},
		{"version",	no_argument,	0,	'v'},
		{"help",	no_argument,	0,	'h'},
		{"log-level",		required_argument,	0,	'l'},
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "p:j:vhl:", options, &option_index);
		if (c < 0) {
			break;
		}
		switch (c) {
		case 'p':
			target_pid = atoi(optarg);
			break;
		case 'j':
			patch_object_file = optarg;
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

	if (patch_object_file && !fexist(patch_object_file)) {
		fprintf(stderr, "%s not exist.\n", patch_object_file);
		exit(1);
	}

	if (!patch_object_file) {
		if (!fexist(ELFTOOLS_FTRACE_OBJ_PATH)) {
			fprintf(stderr,
				"Default ftrace relocatable object %s is not exist.\n"
				"Make sure you install elftools correctly.\n",
				ELFTOOLS_FTRACE_OBJ_PATH
			);
			exit(1);
		}
		fprintf(stderr, "WARNING: use default %s.\n",
			ELFTOOLS_FTRACE_OBJ_PATH);
		patch_object_file = ELFTOOLS_FTRACE_OBJ_PATH;
	}

	if (!fexist(patch_object_file)) {
		fprintf(stderr, "%s is not exist.\n", patch_object_file);
		exit(1);
	}

	if ((ftype(patch_object_file) & FILE_ELF_RELO) != FILE_ELF_RELO) {
		fprintf(stderr, "%s is not ELF or ELF LSB relocatable.\n",
			patch_object_file);
		exit(1);
	}

	return 0;
}


int main(int argc, char *argv[])
{
	int __unused ret = 0;

	elftools_init();

	parse_config(argc, argv);

	set_log_level(config.log_level);

	target_task = open_task(target_pid, FTO_ALL);

	if (!target_task) {
		fprintf(stderr, "open %d failed. %s\n", target_pid, strerror(errno));
		return 1;
	}


	free_task(target_task);

	return 0;
}

