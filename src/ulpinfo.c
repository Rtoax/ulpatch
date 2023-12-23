// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2023 Rong Tao <rtoax@foxmail.com> */
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


static const char *prog_name = "ulpinfo";

static char *patch_file = NULL;
static pid_t pid = 0;

static void print_help(void)
{
	printf(
	"\n"
	" Usage: ulpinfo [OPTION]... [FILE]...\n"
	"\n"
	" User space patch\n"
	"\n"
	" Mandatory arguments to long options are mandatory for short options too.\n"
	"\n"
	" Option argument:\n"
	"\n"
	"  -i, --patch         specify an patch file to check\n"
	"\n"
	"  -p, --pid           list all patches in specified PID process\n"
	"\n");
	print_usage_common(prog_name);
	exit(0);
}

static int parse_config(int argc, char *argv[])
{
	struct option options[] = {
		{ "patch",          required_argument, 0, 'i' },
		{ "pid",            required_argument, 0, 'p' },
		COMMON_OPTIONS
		{ NULL }
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "i:p:"COMMON_GETOPT_OPTSTRING,
				options, &option_index);
		if (c < 0)
			break;

		switch (c) {
		case 'i':
			patch_file = optarg;
			break;
		case 'p':
			pid = atoi(optarg);
			break;
		COMMON_GETOPT_CASES(prog_name)
		default:
			print_help();
			break;
		}
	}

	return 0;
}

int show_patch_info(void)
{
	int err;
	struct load_info info;

	if (!patch_file) {
		fprintf(stderr, "Must specify --patch\n");
		exit(1);
	}
	if (!fexist(patch_file)) {
		fprintf(stderr, "%s is not exist\n", patch_file);
		exit(1);
	}

	err = alloc_patch_file(patch_file, "temp.up", &info);
	if (err) {
		lerror("Parse %s failed.\n", patch_file);
		return err;
	}

	setup_load_info(&info);

	fprintf(stdout, "\tType       : %d\n", info.type);
	print_ulp_strtab(stdout, "\t", &info.ulp_strtab);
	print_ulp_info(stdout, "\t", info.ulp_info);
	fprintf(stdout, "\tBuildID    : %s\n", info.str_build_id);

	release_load_info(&info);

	return 0;
}

int show_task_patch_info(pid_t pid)
{
	int i = 1;
	struct task *task;
	struct vma_ulp *ulp, *tmpulp;

	task = open_task(pid, FTO_ALL);
	if (!task) {
		lerror("Open pid=%d task failed.\n", pid);
		return -ENOENT;
	}

	if (list_empty(&task->ulp_list)) {
		fprintf(stdout, "No ULPatch founded in process %d\n", pid);
		goto free;
	}

	printf("\033[1;7m");
	printf("%-8s %-20s %-16s %-16s", "NUM", "DATE", "VMA_ADDR", "TARGET_FUNC");
	if (config.verbose)
		printf(" %-41s", "Build ID");
	printf("\033[m\n");
	list_for_each_entry_safe(ulp, tmpulp, &task->ulp_list, node) {
		struct vma_struct *vma = ulp->vma;
		printf("%-8d %-20s %-16lx %-16s",
			i, ulp_info_strftime(&ulp->info),
			vma->start, ulp->strtab.dst_func);
		if (config.verbose)
			printf(" %-41s", ulp->str_build_id);
		printf("\n");
		if (config.verbose) {
			print_vma(stdout, vma, 0);
			print_ulp_strtab(stdout, "\t", &ulp->strtab);
			print_ulp_info(stdout, "\t", &ulp->info);
		}
		i++;
	}

free:
	free_task(task);
	return 0;
}

int main(int argc, char *argv[])
{
	parse_config(argc, argv);

	set_log_level(config.log_level);

	if (patch_file)
		show_patch_info();

	if (pid)
		show_task_patch_info(pid);

	return 0;
}
