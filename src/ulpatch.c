// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

#include <elf/elf_api.h>

#include <patch/patch.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>
#include <utils/task.h>

#include "common.c"


enum command {
	CMD_NONE,
	CMD_PATCH,
} command_type = CMD_NONE;


static pid_t target_pid = -1;
static struct task_struct *target_task = NULL;
static char *patch_file = NULL;

enum {
	ARG_MIN = ARG_COMMON_MAX,
	ARG_PATCH,
};

static const char *prog_name = "ulpatch";

int check_patch_file(const char *file);


static void print_help(void)
{
	printf(
	"\n"
	" Usage: ulpatch [OPTION]... [FILE]...\n"
	"\n"
	" User space patch\n"
	"\n"
	" Mandatory arguments to long options are mandatory for short options too.\n"
	"\n"
	" Option argument:\n"
	"\n"
	"  -p, --pid [PID]     specify a process identifier(pid_t)\n"
	"\n"
	" Operate argument:\n"
	"\n"
	"  --patch  [PATCH]    patch an object file into target task, and patch\n"
	"                      the patch.\n"
	"\n");
	print_usage_common(prog_name);
	exit(0);
}

static int parse_config(int argc, char *argv[])
{
	int ret;

	struct option options[] = {
		{ "pid",            required_argument, 0, 'p' },
		{ "patch",          required_argument, 0, ARG_PATCH },
		COMMON_OPTIONS
		{ NULL }
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "p:"COMMON_GETOPT_OPTSTRING,
				options, &option_index);
		if (c < 0)
			break;

		switch (c) {
		case 'p':
			target_pid = atoi(optarg);
			break;
		case ARG_PATCH:
			command_type = CMD_PATCH;
			patch_file = strdup(optarg);
			break;
		COMMON_GETOPT_CASES(prog_name, print_help)
		default:
			print_help();
			exit(1);
			break;
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

	/* check patch file */
	if (command_type == CMD_PATCH) {
		ret = check_patch_file(patch_file);
		if (ret) {
			fprintf(stderr, "Check %s failed.\n", patch_file);
			exit(1);
		}
	}

	return 0;
}

int check_patch_file(const char *file)
{
	int err = 0;
	struct load_info info = {0};

	if (!file)
		return -EEXIST;

	if (file && !fexist(file)) {
		ldebug("%s is not exist.\n", file);
		return -EEXIST;
	}
	err = alloc_patch_file(patch_file, "temp.up", &info);
	if (err) {
		lerror("Parse %s failed.\n", patch_file);
		return err;
	}

	err = setup_load_info(&info);
	if (err) {
		ldebug("Load %s failed\n", file);
		err = -ENODATA;
		goto release;
	}

	if (strcmp(info.ulp_strtab.magic, SEC_ULPATCH_MAGIC)) {
		ldebug("%s is not ulpatch file.\n", file);
		err = -ENODATA;
	}

release:
	release_load_info(&info);
	return err;
}

static int command_patch(void)
{
	return init_patch(target_task, patch_file);
}

int main(int argc, char *argv[])
{
	parse_config(argc, argv);

	ulpatch_env_init();

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
	if (patch_file)
		free(patch_file);

	return 0;
}

