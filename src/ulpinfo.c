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

static void print_ulp_strtab(struct ulpatch_strtab *strtab)
{
	printf("%-16s : %s\n", "Magic", strtab->magic);
	printf("%-16s : %s\n", "SrcFunc", strtab->src_func);
	printf("%-16s : %s\n", "DstFunc", strtab->dst_func);
	printf("%-16s : %s\n", "Author", strtab->author);
}

static void print_ulp_info(struct ulpatch_info *inf)
{
	printf("TargetAddr : %#016lx\n", inf->target_func_addr);
	printf("PatchAddr  : %#016lx\n", inf->patch_func_addr);
	printf("VirtAddr   : %#016lx\n", inf->virtual_addr);
	printf("OrigVal    : %#016lx\n", inf->orig_value);
	printf("Flags      : %#08x\n",  inf->flags);
	printf("Version    : %#08x\n",  inf->ulpatch_version);
	printf("Pad[4]     : [%d,%d,%d,%d]\n",
		inf->pad[0], inf->pad[1],
		inf->pad[2], inf->pad[3]);
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

	printf("%-16s : %d\n", "Type", info.type);
	print_ulp_strtab(&info.ulp_strtab);
	print_ulp_info(info.ulp_info);

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
		print_ulp_strtab(&ulp->strtab);
		print_ulp_info(&ulp->info);
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

