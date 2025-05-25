// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

#include "elf/elf-api.h"

#include "patch/patch.h"

#include "utils/ansi.h"
#include "utils/log.h"
#include "utils/list.h"
#include "utils/compiler.h"
#include "task/task.h"
#include "cmds.h"

#include <args-common.c>


static const char *prog_name = "ulpinfo";

static char *patch_file = NULL;
static pid_t pid = 0;

static void ulpinfo_args_reset(void)
{
	patch_file = NULL;
	pid = 0;
}

static int print_help(void)
{
	printf(
	"\n"
	" Usage: ulpinfo [OPTION]... [FILE]...\n"
	"\n"
	" ulpinfo is used to view the patch information of the target process,\n"
	" including the patch ID and patch objective function. Usually used in\n"
	" conjunction with ulpatch. At the same time, you can view the local \n"
	" ulp.elf patch file.\n"
	"\n"
	" Option argument:\n"
	"\n"
	"  -i, --patch [FILE]  specify an patch file to check\n"
	"\n"
	"  -p, --pid [PID]     list all patches in specified PID process\n"
	"\n");
	print_usage_common(prog_name);
	cmd_exit_success();
	return 0;
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
		COMMON_GETOPT_CASES(prog_name, print_help, argv)
		default:
			print_help();
			cmd_exit(1);
			break;
		}
	}

	return 0;
}

int show_file_patch_info(void)
{
	int err;
	struct load_info info;
	char *tmp_ulp = "temp.ulp";

	if (!patch_file) {
		fprintf(stderr, "Must specify --patch\n");
		cmd_exit(1);
	}
	if (!fexist(patch_file)) {
		fprintf(stderr, "%s is not exist\n", patch_file);
		cmd_exit(1);
	}

	memset(&info, 0x0, sizeof(info));

	err = alloc_patch_file(patch_file, tmp_ulp, &info);
	if (err) {
		ulp_error("Parse %s failed.\n", patch_file);
		return err;
	}

	err = setup_load_info(&info);
	if (err)
		return err;

	fprintf(stdout, "\tFile: %s\n", patch_file);
	print_ulp_strtab(stdout, "\t", &info.ulp_strtab);
	print_ulp_author(stdout, "\t", &info.ulp_author);
	print_ulp_license(stdout, "\t", &info.ulp_license);
	print_ulp_info(stdout, "\t", info.ulp_info);
	fprintf(stdout, "\tBuildID    : %s\n", info.str_build_id);

	release_load_info(&info);

	fremove(tmp_ulp);
	return 0;
}

int show_task_patch_info(pid_t pid)
{
	int i = 1;
	struct task_struct *task;
	struct vma_ulp *ulp, *tmpulp;

	task = open_task(pid, FTO_ALL & ~FTO_RDWR);
	if (!task) {
		ulp_error("Open pid=%d task failed.\n", pid);
		return -ENOENT;
	}

	if (list_empty(&task->ulp_root.list)) {
		fprintf(stdout, "No ULPatch founded in process %d\n", pid);
		goto free;
	}

	fpansi_bold(stdout);
	printf("COMM: %s\n", task->exe);
	printf("PID: %d\n", task->pid);
	fpansi_reset(stdout);

	fpansi_bold(stdout);
	fpansi_reverse(stdout);
	printf("%-4s %-4s %-20s %-16s %-16s", "NUM", "ID", "DATE", "VMA_START",
	       "TARGET_FUNC");
	if (is_verbose())
		printf(" %-41s", "Build ID");
	fpansi_reset(stdout);
	printf("\n");

	list_for_each_entry_safe(ulp, tmpulp, &task->ulp_root.list, node) {
		struct vm_area_struct *vma = ulp->vma;
		printf("%-4d %-4d %-20s %#016lx %-16s",
			i, ulp->info.ulp_id, ulp_info_strftime(&ulp->info),
			vma->vm_start, ulp->strtab.dst_func);

		if (is_verbose())
			printf(" %-41s", ulp->str_build_id);

		printf("\n");

		if (is_verbose()) {
			fpansi_gray(stdout);
			print_vma(stdout, false, vma, 0);
			print_ulp_strtab(stdout, "\t", &ulp->strtab);
			print_ulp_author(stdout, "\t", &ulp->author);
			print_ulp_license(stdout, "\t", &ulp->license);
			print_ulp_info(stdout, "\t", &ulp->info);
			fprintf(stdout, "\n");
			fpansi_reset(stdout);
		}
		i++;
	}

free:
	close_task(task);
	return 0;
}

int ulpinfo(int argc, char *argv[])
{
	int ret;

	COMMON_RESET_BEFORE_PARSE_ARGS(ulpinfo_args_reset);

	ret = parse_config(argc, argv);
#if !defined(ULP_CMD_MAIN)
	if (ret == CMD_RETURN_SUCCESS_VALUE)
		return 0;
#endif
	if (ret)
		return ret;

	COMMON_IN_MAIN_AFTER_PARSE_ARGS();

	ulpatch_init();

	if (!patch_file && !pid) {
		fprintf(stderr, "Must specify ulp file or pid, see -h.\n");
		return -EINVAL;
	}

	if (patch_file)
		ret = show_file_patch_info();
	else if (pid)
		ret = show_task_patch_info(pid);

	return ret;
}

#if defined(ULP_CMD_MAIN)
int main(int argc, char *argv[])
{
	return ulpinfo(argc, argv);
}
#endif
