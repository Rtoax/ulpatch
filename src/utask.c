// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <elf/elf_api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <utils/compiler.h>


struct config config = {
	.log_level = -1,
};

enum {
	ARG_LOG_LEVEL = 200,
	ARG_LOG_DEBUG,
	ARG_LOG_ERR,
	ARG_DUMP_VMAS, // print all vmas
	ARG_DUMP_VMA, // dump one vma
	ARG_FILE_MAP_TO_VMA,
	ARG_FILE_UNMAP_FROM_VMA,
	ARG_LIST_SYMBOLS,
};

static pid_t target_pid = -1;

static bool flag_dump_vmas = false;
static bool flag_dump_vma = false;
static bool flag_unmap_vma = false;
static const char *map_file = NULL;
static unsigned long vma_addr = 0;
static bool flag_list_symbols = false;
static const char *output_file = NULL;

static struct task *target_task = NULL;

static const char *prog_name = "utask";


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
	"  --dump-vmas         dump vmas\n"
	"  --dump-vma          save VMA address space to console or to a file,\n"
	"                      need to specify address of a VMA. check with -v.\n"
	"                      the input will be take as base 16, default output\n"
	"                      is stdout, write(2), specify output file with -o.\n"
	"\n"
	"  --map-file          mmap a exist file into target process address space\n"
	"  --unmap-file        munmap a exist VMA, the argument need input vma address.\n"
	"                      and witch is mmapped by --map-file.\n"
	"                      check with --dump-vmas and --map-file.\n"
	"\n"
	"  --symbols           list all symbols\n"
	"\n"
	"  -o, --output        specify output filename.\n"
	"\n"
	"\n"
	" Other argument:\n"
	"\n"
	"  --log-level         set log level, default(%d)\n"
	"                      EMERG(%d),ALERT(%d),CRIT(%d),ERR(%d),WARN(%d)\n"
	"                      NOTICE(%d),INFO(%d),DEBUG(%d)\n"
	"  --log-debug         set log level to DEBUG(%d)\n"
	"  --log-error         set log level to ERR(%d)\n"
	"\n"
	"  -h, --help          display this help and exit\n"
	"  -v, --version       output version information and exit\n"
	"\n"
	" utask %s\n",
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
		{ "dump-vmas",      no_argument,       0, ARG_DUMP_VMAS },
		{ "dump-vma",       required_argument, 0, ARG_DUMP_VMA },
		{ "map-file",       required_argument, 0, ARG_FILE_MAP_TO_VMA },
		{ "unmap-file",     required_argument, 0, ARG_FILE_UNMAP_FROM_VMA },
		{ "symbols",        no_argument,       0, ARG_LIST_SYMBOLS },
		{ "output",         required_argument, 0, 'o' },
		{ "version",        no_argument,       0, 'v' },
		{ "help",           no_argument,       0, 'h' },
		{ "log-level",      required_argument, 0, ARG_LOG_LEVEL },
		{ "log-debug",      no_argument,       0, ARG_LOG_DEBUG },
		{ "log-error",      no_argument,       0, ARG_LOG_ERR },
		{ NULL }
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "p:o:hv", options, &option_index);
		if (c < 0) {
			break;
		}
		switch (c) {
		case 'p':
			target_pid = atoi(optarg);
			break;
		case ARG_DUMP_VMAS:
			flag_dump_vmas = true;
			break;
		case ARG_DUMP_VMA:
			flag_dump_vma = true;
			vma_addr = strtoull(optarg, NULL, 16);
			if (vma_addr == 0) {
				fprintf(stderr, "Wrong address for --dump-vma.\n");
				exit(1);
			}
			break;
		case ARG_FILE_MAP_TO_VMA:
			map_file = optarg;
			break;
		case ARG_FILE_UNMAP_FROM_VMA:
			flag_unmap_vma = true;
			vma_addr = strtoull(optarg, NULL, 16);
			break;
		case ARG_LIST_SYMBOLS:
			flag_list_symbols = true;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'v':
			printf("%s %s\n", prog_name, upatch_version());
			exit(0);
		case 'h':
			print_help();
			break;
		case ARG_LOG_LEVEL:
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
			break;
		}
	}

	if (!flag_dump_vmas &&
		!flag_dump_vma &&
		!map_file &&
		!flag_unmap_vma &&
		!flag_list_symbols) {
		fprintf(stderr, "nothing to do, -h, --help.\n");
		exit(1);
	}

	if (flag_dump_vma && !output_file) {
		fprintf(stderr, "--dump-vma need output file(-o).\n");
		exit(1);
	}

	if (map_file && !fexist(map_file)) {
		fprintf(stderr, "%s is not exist.\n", map_file);
		exit(1);
	}

	if (output_file && fexist(output_file)) {
		fprintf(stderr, "%s is already exist.\n", output_file);
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

static int mmap_a_file(void)
{
	int ret = 0;
	ssize_t map_len = fsize(map_file);
	unsigned long __unused map_v;
	int __unused map_fd;
	const char *filename = map_file;

	struct task *task = target_task;

	task_attach(task->pid);

	map_fd = task_open(task, (char *)filename, O_RDWR, 0644);
	if (map_fd <= 0) {
		fprintf(stderr, "ERROR: remote open failed.\n");
		return -1;
	}

	ret = task_ftruncate(task, map_fd, map_len);
	if (ret != 0) {
		fprintf(stderr, "ERROR: remote ftruncate failed.\n");
		goto close_ret;
	}

	map_v = task_mmap(task,
				0UL, map_len,
				PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_PRIVATE, map_fd, 0);
	if (!map_v) {
		fprintf(stderr, "ERROR: remote mmap failed.\n");
		goto close_ret;
	}

	task_detach(task->pid);

	update_task_vmas(task);

close_ret:
	task_close(task, map_fd);

	return ret;
}

static int munmap_an_vma(void)
{
	size_t size = 0;
	struct task *task = target_task;
	unsigned long addr = 0;

	struct vma_struct *vma = find_vma(task, vma_addr);
	if (!vma) {
		fprintf(stderr, "vma not exist.\n");
		return -1;
	}

	if (fexist(vma->name_)) {
		size = fsize(vma->name_);
	} else {
		size = vma->end - vma->start;
	}
	addr = vma->start;

	task_attach(task->pid);
	task_munmap(task, addr, size);
	task_detach(task->pid);

	return 0;
}

static void list_all_symbol(void)
{
	int max_name_len = 0;
	struct symbol *sym, *tmp;

	/* Get vma name strlen for pretty print */
	rbtree_postorder_for_each_entry_safe(sym, tmp,
		&target_task->vma_symbols, node) {

		int len = strlen(basename(sym->vma->name_));
		if (max_name_len < len)
			max_name_len = len;
	}

	printf(
	"%-*s %-16s %-16s %-8s %-8s %-8s %-32s\n",
	max_name_len, "VMA",
	"ADDR", "ST_VALUE", "ST_SIZE", "BIND", "TYPE", "SYMBOL"
	);

	rbtree_postorder_for_each_entry_safe(sym, tmp,
		&target_task->vma_symbols, node) {

		printf(
			"%-*s %#016lx %#016lx %-8ld %-8s %-8s %s\n",
			max_name_len, basename(sym->vma->name_),
			task_vma_symbol_value(sym),
			sym->sym.st_value,
			sym->sym.st_size,
			st_bind_string(&sym->sym),
			st_type_string(&sym->sym),
			sym->name
		);
	}
}

int main(int argc, char *argv[])
{
	parse_config(argc, argv);

	upatch_init();

	set_log_level(config.log_level);

	target_task = open_task(target_pid, FTO_ALL);
	if (!target_task) {
		fprintf(stderr, "open pid %d failed. %s\n", target_pid, strerror(errno));
		return 1;
	}

	if (map_file) {
		mmap_a_file();
	}

	if (flag_unmap_vma) {
		munmap_an_vma();
	}

	/* dump target task VMAs from /proc/PID/maps */
	if (flag_dump_vmas)
		dump_task_vmas(target_task);

	/* dump an VMA */
	if (flag_dump_vma) {
		dump_task_vma_to_file(output_file, target_task, vma_addr);
	}

	if (flag_list_symbols) {
		list_all_symbol();
	}

	free_task(target_task);

	return 0;
}

