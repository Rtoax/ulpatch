// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

#include <elf/elf-api.h>

#include <patch/patch.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>
#include <task/task.h>
#include <utils/cmds.h>

#include <args-common.c>


enum command {
	CMD_NONE,
	CMD_PATCH,
	CMD_UNPATCH,
} command_type = CMD_NONE;


static pid_t target_pid = -1;
static struct task_struct *target_task = NULL;
static char *patch_file = NULL;

enum {
	ARG_MIN = ARG_COMMON_MAX,
	ARG_PATCH,
	ARG_UNPATCH,
};

static const char *prog_name = "ulpatch";

int check_patch_file(const char *file);

static void args_reset(void)
{
	target_pid = -1;
	target_task = NULL;
	patch_file = NULL;
}

static int print_help(void)
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
	"  --unpatch           unpatch the latest ulpatch from target task.\n"
	"\n");
	print_usage_common(prog_name);
	cmd_exit_success();
	return 0;
}

static int parse_config(int argc, char *argv[])
{
	int ret;

	struct option options[] = {
		{ "pid",            required_argument, 0, 'p' },
		{ "patch",          required_argument, 0, ARG_PATCH },
		{ "unpatch",        no_argument,       0, ARG_UNPATCH },
		COMMON_OPTIONS
		{ NULL }
	};

	reset_getopt();

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
		case ARG_UNPATCH:
			command_type = CMD_UNPATCH;
			break;
		COMMON_GETOPT_CASES(prog_name, print_help, argv)
		default:
			print_help();
			cmd_exit(1);
			break;
		}
	}

	if (command_type == CMD_NONE) {
		fprintf(stderr, "Nothing to do, check -h, --help.\n");
		cmd_exit(1);
	}

	if (target_pid == -1) {
		fprintf(stderr, "Specify pid with -p, --pid.\n");
		cmd_exit(1);
	}

	if (!proc_pid_exist(target_pid)) {
		fprintf(stderr, "pid %d not exist.\n", target_pid);
		cmd_exit(1);
	}

	/* check patch file */
	if (command_type == CMD_PATCH) {
		ret = check_patch_file(patch_file);
		if (ret) {
			fprintf(stderr, "Check %s failed.\n", patch_file);
			cmd_exit(1);
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
		ulp_debug("%s is not exist.\n", file);
		return -EEXIST;
	}
	err = alloc_patch_file(patch_file, "temp.ulp", &info);
	if (err) {
		ulp_error("Parse %s failed.\n", patch_file);
		return err;
	}

	err = setup_load_info(&info);
	if (err) {
		ulp_debug("Load %s failed\n", file);
		err = -ENODATA;
		goto release;
	}

	if (strcmp(info.ulp_strtab.magic, SEC_ULPATCH_MAGIC)) {
		ulp_debug("%s is not ulpatch file.\n", file);
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

static int command_unpatch(void)
{
	return delete_patch(target_task);
}

int ulpatch(int argc, char *argv[])
{
	int ret;

	args_reset();
	COMMON_RESET();

	ret = parse_config(argc, argv);
#if !defined(ULP_CMD_MAIN)
	if (ret == CMD_RETURN_SUCCESS_VALUE)
		return 0;
#endif
	if (ret)
		return ret;

	COMMON_IN_MAIN();

	ulpatch_init();

	target_task = open_task(target_pid, FTO_ALL);

	if (!target_task) {
		fprintf(stderr, "open %d failed. %m\n", target_pid);
		return 1;
	}

	switch (command_type) {
	case CMD_PATCH:
		command_patch();
		break;
	case CMD_UNPATCH:
		command_unpatch();
		break;
	case CMD_NONE:
	default:
		fprintf(stderr, "What to do.\n");
	}

	close_task(target_task);
	if (patch_file)
		free(patch_file);

	return 0;
}

#if defined(ULP_CMD_MAIN)
int main(int argc, char *argv[])
{
	return ulpatch(argc, argv);
}
#endif
