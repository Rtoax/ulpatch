// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <elf/elf_api.h>
#include <cli/cli_api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <utils/compiler.h>


struct config config = {
	.log_level = -1,
};

#define ARG_VERSION	100


static pid_t target_pid = -1;

static bool flag_dump_vmas = false;
static bool flag_dump_vma = false;
static const char *map_file = NULL;
static unsigned long dump_vma_addr = 0;
static const char *output_file = NULL;

static struct task *target_task = NULL;

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
	"  -v, --dump-vmas     dump vmas\n"
	"  -V, --dump-vma      save VMA address space to console or to a file,\n"
	"                      need to specify address of a VMA. check with -v.\n"
	"                      the input will be take as base 16, default output\n"
	"                      is stdout, write(2), specify output file with -o.\n"
	"\n"
	"  -f, --map-file      mmap a exist file into target process address space\n"
	"\n"
	"  -o, --output        specify output filename.\n"
	"\n"
	" Other argument:\n"
	"\n"
	"  -l, --log-level     set log level, default(%d)\n"
	"                      EMERG(%d),ALERT(%d),CRIT(%d),ERR(%d),WARN(%d)\n"
	"                      NOTICE(%d),INFO(%d),DEBUG(%d)\n"
	"  -h, --help          display this help and exit\n"
	"  --version           output version information and exit\n"
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
		{"dump-vmas",	no_argument,	0,	'v'},
		{"dump-vma",	required_argument,	0,	'V'},
		{"map-file",		required_argument,	0,	'f'},
		{"output",	required_argument,	0,	'o'},
		{"version",	no_argument,	0,	ARG_VERSION},
		{"help",	no_argument,	0,	'h'},
		{"log-level",		required_argument,	0,	'l'},
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "p:vV:f:o:hl:", options, &option_index);
		if (c < 0) {
			break;
		}
		switch (c) {
		case 'p':
			target_pid = atoi(optarg);
			break;
		case 'v':
			flag_dump_vmas = true;
			break;
		case 'V':
			flag_dump_vma = true;
			dump_vma_addr = strtoull(optarg, NULL, 16);
			break;
		case 'f':
			map_file = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		case ARG_VERSION:
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

	if (!flag_dump_vmas && !flag_dump_vma) {
		fprintf(stderr, "nothing to do, -h, --help.\n");
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

static int dump_an_vma(void)
{
	size_t vma_size = 0;
	void *mem = NULL;

	/* default is stdout */
	int nbytes;
	int fd = fileno(stdout);

	if (output_file) {
		fd = open(output_file, O_CREAT | O_RDWR, 0664);
		if (fd <= 0) {
			fprintf(stderr, "open %s: %s\n", output_file, strerror(errno));
			return -1;
		}
	}
	struct vma_struct *vma = find_vma(target_task, dump_vma_addr);
	if (!vma) {
		fprintf(stderr, "vma not exist.\n");
		return -1;
	}

	vma_size = vma->end - vma->start;

	mem = malloc(vma_size);

	memcpy_from_task(target_task, mem, vma->start, vma_size);

	/* write to file or stdout */
	nbytes = write(fd, mem, vma_size);
	if (nbytes != vma_size) {
		fprintf(stderr, "write failed, %s.\n", strerror(errno));
		free(mem);
		return -1;
	}

	free(mem);
	if (fd != fileno(stdout))
		close(fd);

	return 0;
}

int main(int argc, char *argv[])
{
	elftools_init();

	parse_config(argc, argv);

	set_log_level(config.log_level);

	target_task = open_task(target_pid, FTO_ALL);

	if (!target_task) {
		fprintf(stderr, "open %d failed. %s\n", target_pid, strerror(errno));
		return 1;
	}

	if (map_file) {
		// TODO
	}

	/* dump target task VMAs from /proc/PID/maps */
	if (flag_dump_vmas)
		dump_task_vmas(target_task);

	/* dump an VMA */
	if (flag_dump_vma) {
		dump_an_vma();
	}

	free_task(target_task);

	return 0;
}

