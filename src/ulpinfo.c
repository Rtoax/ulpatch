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

	err = parse_load_info(patch_file, "temp.up", &info);
	if (err) {
		lerror("Parse %s failed.\n", patch_file);
		return err;
	}

	setup_load_info(&info);

	printf("%-16s : %s\n", "Magic", info.ulpatch_strtab.magic);
	printf("%-16s : %d\n", "Type", info.type);
	printf("%-16s : %s\n", "SrcFunc", info.ulpatch_strtab.src_func);
	printf("%-16s : %s\n", "DstFunc", info.ulpatch_strtab.dst_func);
	printf("%-16s : %s\n", "Author", info.ulpatch_strtab.author);

	printf("TargetAddr : %#016lx\n", info.info->target_func_addr);
	printf("PatchAddr  : %#016lx\n", info.info->patch_func_addr);
	printf("VirtAddr   : %#016lx\n", info.info->virtual_addr);
	printf("OrigVal    : %#016lx\n", info.info->orig_value);
	printf("Flags      : %#08x\n",  info.info->flags);
	printf("Version    : %#08x\n",  info.info->ulpatch_version);
	printf("Pad[4]     : [%d,%d,%d,%d]\n",
		info.info->pad[0], info.info->pad[1],
		info.info->pad[2], info.info->pad[3]);

	release_load_info(&info);

	return 0;
}

int show_task_patch_info(pid_t pid)
{
	struct task *task;
	struct vma_ulp *ulp, *tmpulp;

	task = open_task(pid, FTO_ALL);
	if (!task) {
		lerror("Open pid=%d task failed.\n", pid);
		return -ENOENT;
	}

	list_for_each_entry_safe(ulp, tmpulp, &task->ulp_list, node) {
		struct vma_struct *vma = ulp->vma;
		print_vma(stdout, vma, 0);
		lerror("TODO: Print ulpatch info.\n");
	}

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

