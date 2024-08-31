// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <elf/elf-api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <utils/disasm.h>
#include <utils/compiler.h>

#include <patch/patch.h>

#include <args-common.c>


enum {
	ARG_MIN = ARG_COMMON_MAX,
	ARG_JMP_FROM_ADDR,
	ARG_JMP_TO_ADDR,
	ARG_VMAS,
	ARG_DUMP_VMA,
	ARG_DUMP_ADDR,
	ARG_DUMP_SIZE,
	ARG_FILE_MAP_TO_VMA,
	ARG_FILE_UNMAP_FROM_VMA,
	ARG_THREADS,
	ARG_FDS,
	ARG_AUXV,
	ARG_STATUS,
	ARG_LIST_SYMBOLS,
	ARG_DISASM_ADDR,
	ARG_DISASM_SIZE,
};

static pid_t target_pid = -1;

static bool flag_print_task = true;
static bool flag_print_vmas = false;
static bool flag_dump_vma = false;
static bool flag_dump_addr = false;
static bool flag_unmap_vma = false;
static const char *map_file = NULL;
static unsigned long vma_addr = 0;
static unsigned long dump_addr = 0;
static unsigned long dump_size = 0;
static unsigned long jmp_addr_from = 0;
static unsigned long jmp_addr_to = 0;
static bool flag_list_symbols = false;
static bool flag_print_threads = false;
static bool flag_print_fds = false;
static bool flag_print_auxv = false;
static bool flag_print_status = false;
static bool flag_disasm = false;
static unsigned long disasm_addr = 0;
static unsigned long disasm_size = 0;
static const char *output_file = NULL;
/* Default: read only */
static bool flag_rdonly = true;

static struct task_struct *target_task = NULL;

static const char *prog_name = "ultask";


static void print_help(void)
{
	printf(
	"\n"
	" Usage: ultask [OPTION]... [FILE]...\n"
	"\n"
	" User space task\n"
	"\n"
	" Mandatory arguments to long options are mandatory for short options too.\n"
	"\n"
	" Essential argument:\n"
	"\n"
	"  -p, --pid [PID]     specify a process identifier(pid_t)\n"
	"\n"
	"  --vmas              print all vmas\n"
	"                      show detail if specify verbose argument.\n"
	"  --dump-vma [ADDR]   save VMA address space to console or to a file,\n"
	"                      need to specify address of a VMA. check with -v.\n"
	"                      the input will be take as base 16, default output\n"
	"                      is stdout, write(2), specify output file with -o.\n"
	"\n"
	"  --dump-addr [ADDR]  dump address memory to file, need --dump-size\n"
	"\n"
	"  --dump-size [SIZE]  dump size\n"
	"\n"
	"  --jmp-from [ADDR]   specify a jump entry SRC address\n"
	"  --jmp-to   [ADDR]   specify a jump entry DST address\n"
	"                      you better ensure what you are doing.\n"
	"\n"
	"  --threads           dump threads\n"
	"  --fds               dump fds\n"
	"  --auxv              print auxv of task\n"
	"  --status            print status of task\n"
	"\n"
	"  --map-file [FILE]   mmap a exist file into target process address space\n"
	"  --unmap-file        munmap a exist VMA, the argument need input vma address.\n"
	"                      and witch is mmapped by --map-file.\n"
	"                      check with --vmas and --map-file.\n"
	"\n"
	"  --symbols           list all symbols\n"
	"\n"
	"  --disasm-addr [ADDR]\n"
	"                      disassemble a piece of code in a running process.\n"
	"  --disasm-size [SIZE]\n"
	"                      specify disassemble size.\n"
	"\n"
	"  -o, --output        specify output filename.\n"
	"\n");
	printf(
	" FORMAT\n"
	"  ADDR: 0x123, 123\n"
	"  SIZE: 123, 0x123, 123GB, 123KB, 123MB, 0x123MB\n"
	"\n"
	);
	print_usage_common(prog_name);
	exit(0);
}

static int parse_config(int argc, char *argv[])
{
	struct option options[] = {
		{ "pid",            required_argument, 0, 'p' },
		{ "vmas",           no_argument,       0, ARG_VMAS },
		{ "threads",        no_argument,       0, ARG_THREADS },
		{ "fds",            no_argument,       0, ARG_FDS },
		{ "auxv",           no_argument,       0, ARG_AUXV },
		{ "status",         no_argument,       0, ARG_STATUS },
		{ "dump-vma",       required_argument, 0, ARG_DUMP_VMA },
		{ "dump-addr",      required_argument, 0, ARG_DUMP_ADDR },
		{ "dump-size",      required_argument, 0, ARG_DUMP_SIZE },
		{ "jmp-from",       required_argument, 0, ARG_JMP_FROM_ADDR },
		{ "jmp-to",         required_argument, 0, ARG_JMP_TO_ADDR },
		{ "map-file",       required_argument, 0, ARG_FILE_MAP_TO_VMA },
		{ "unmap-file",     required_argument, 0, ARG_FILE_UNMAP_FROM_VMA },
		{ "symbols",        no_argument,       0, ARG_LIST_SYMBOLS },
		{ "disasm-addr",    required_argument, 0, ARG_DISASM_ADDR },
		{ "disasm-size",    required_argument, 0, ARG_DISASM_SIZE },
		{ "output",         required_argument, 0, 'o' },
		COMMON_OPTIONS
		{ NULL }
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "p:o:"COMMON_GETOPT_OPTSTRING,
				options, &option_index);
		if (c < 0)
			break;

		switch (c) {
		case 'p':
			target_pid = atoi(optarg);
			break;
		case ARG_VMAS:
			flag_print_vmas = true;
			break;
		case ARG_DUMP_VMA:
			flag_dump_vma = true;
			vma_addr = str2addr(optarg);
			if (vma_addr == 0) {
				fprintf(stderr, "Wrong address for --dump-vma.\n");
				exit(1);
			}
			break;
		case ARG_DUMP_ADDR:
			flag_dump_addr = true;
			dump_addr = str2addr(optarg);
			if (dump_addr == 0) {
				fprintf(stderr, "Wrong address for --dump-addr.\n");
				exit(1);
			}
			break;
		case ARG_DUMP_SIZE:
			dump_size = str2size(optarg);
			if (dump_size == 0) {
				fprintf(stderr, "Wrong value for --dump-size.\n");
				exit(1);
			}
			break;
		case ARG_JMP_FROM_ADDR:
			flag_rdonly = false;
			jmp_addr_from = str2addr(optarg);
			if (jmp_addr_from == 0) {
				fprintf(stderr, "Wrong address for --jmp-from.\n");
				exit(1);
			}
			break;
		case ARG_JMP_TO_ADDR:
			flag_rdonly = false;
			jmp_addr_to = str2addr(optarg);
			if (jmp_addr_to == 0) {
				fprintf(stderr, "Wrong address for --jmp-to.\n");
				exit(1);
			}
			break;
		case ARG_FILE_MAP_TO_VMA:
			map_file = optarg;
			flag_rdonly = false;
			break;
		case ARG_FILE_UNMAP_FROM_VMA:
			flag_unmap_vma = true;
			flag_rdonly = false;
			vma_addr = str2addr(optarg);
			break;
		case ARG_LIST_SYMBOLS:
			flag_list_symbols = true;
			break;
		case ARG_THREADS:
			flag_print_threads = true;
			break;
		case ARG_FDS:
			flag_print_fds = true;
			break;
		case ARG_AUXV:
			flag_print_auxv = true;
			break;
		case ARG_STATUS:
			flag_print_status = true;
			break;
		case ARG_DISASM_ADDR:
			flag_disasm = true;
			disasm_addr = str2addr(optarg);
			if (disasm_addr == 0) {
				fprintf(stderr, "Invalid --disasm-addr argument.\n");
				exit(1);
			}
			break;
		case ARG_DISASM_SIZE:
			disasm_size = str2size(optarg);
			if (disasm_size == 0) {
				fprintf(stderr, "Wrong value for --disasm-size.\n");
				exit(1);
			}
			break;
		case 'o':
			output_file = optarg;
			break;
		COMMON_GETOPT_CASES(prog_name, print_help)
		default:
			print_help();
			exit(1);
			break;
		}
	}

	/**
	 * It is necessary to specify a valid process ID.
	 */
	if (target_pid == -1) {
		fprintf(stderr, "Specify pid with -p, --pid.\n");
		exit(1);
	}

	if (!proc_pid_exist(target_pid)) {
		fprintf(stderr, "pid %d not exist.\n", target_pid);
		exit(1);
	}

	/**
	 * There needs to be one action, or more than one action.
	 */
	if (!flag_print_vmas &&
		!flag_dump_vma &&
		!flag_dump_addr &&
		!map_file &&
		(!jmp_addr_from || !jmp_addr_to) &&
		!flag_unmap_vma &&
		!flag_list_symbols &&
		!flag_print_auxv &&
		!flag_print_status &&
		!flag_print_threads &&
		!flag_disasm &&
		!flag_print_fds) {
		if ((!jmp_addr_from && jmp_addr_to) || \
			(jmp_addr_from && !jmp_addr_to)) {
			fprintf(stderr, "must specify --jmp-from and --jmp-to at the same time.\n");
			exit(1);
		}
		fprintf(stderr, "nothing to do, -h, --help.\n");
	} else {
		/**
		 * If no command line arguments are specified, some task
		 * information will be printed by default, but if command line
		 * arguments are specified, it will not be printed.
		 */
		flag_print_task = false;
	}

	if (flag_dump_vma && !output_file) {
		fprintf(stderr, "--dump-vma need output file(-o).\n");
		exit(1);
	}

	if (flag_dump_addr && !output_file) {
		fprintf(stderr, "--dump-addr need output file(-o).\n");
		exit(1);
	}

	if (flag_dump_addr && (!dump_addr || !dump_size)) {
		fprintf(stderr, "--dump-addr need --dump-size.\n");
		exit(1);
	}

	if (flag_disasm && disasm_addr && !disasm_size) {
		fprintf(stderr, "need --disasm-size if disassemble\n");
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

	return 0;
}

static int mmap_a_file(void)
{
	int ret = 0;
	ssize_t map_len = fsize(map_file);
	unsigned long __unused map_v;
	int __unused map_fd;
	const char *filename = map_file;

	struct task_struct *task = target_task;

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

	map_v = task_mmap(task, 0UL, map_len,
			  PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE,
			  map_fd, 0);
	if (!map_v) {
		fprintf(stderr, "ERROR: remote mmap failed.\n");
		goto close_ret;
	}

	task_detach(task->pid);

	update_task_vmas_ulp(task);

close_ret:
	task_close(task, map_fd);

	return ret;
}

static int munmap_an_vma(void)
{
	size_t size = 0;
	struct task_struct *task = target_task;
	unsigned long addr = 0;

	struct vm_area_struct *vma = find_vma(task, vma_addr);
	if (!vma) {
		fprintf(stderr, "vma not exist.\n");
		return -1;
	}

	if (fexist(vma->name_)) {
		size = fsize(vma->name_);
	} else {
		size = vma->vm_end - vma->vm_start;
	}
	addr = vma->vm_start;

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

	printf("%-*s %-16s %-16s %-8s %-8s %-18s %-4s %-32s\n",
		max_name_len, "VMA",
		"ADDR", "ST_VALUE", "ST_SIZE", "BIND", "TYPE(rb)", "IDX", "SYMBOL");

	rbtree_postorder_for_each_entry_safe(sym, tmp,
					     &target_task->vma_symbols, node) {

		printf("%-*s %#016lx %#016lx %-8ld %-8s %-8s(%-8s) %-4d %s\n",
			max_name_len, basename(sym->vma->name_),
			task_vma_symbol_vaddr(sym),
			sym->sym.st_value,
			sym->sym.st_size,
			st_bind_string(&sym->sym),
			st_type_string(&sym->sym),
			i_st_type_string(sym->type),
			sym->sym.st_shndx,
			sym->name);
	}
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int flags = FTO_ALL;

	parse_config(argc, argv);

	ulpatch_init();

	set_log_level(config.log_level);

	if (flag_rdonly)
		flags &= ~FTO_RDWR;

	target_task = open_task(target_pid, flags);
	if (!target_task) {
		fprintf(stderr, "open pid %d failed. %m\n", target_pid);
		return 1;
	}

	if (flag_print_task)
		print_task(stdout, target_task, config.verbose);

	if (map_file)
		mmap_a_file();

	if (flag_unmap_vma)
		munmap_an_vma();

	if (flag_print_auxv)
		print_task_auxv(stdout, target_task);

	if (flag_print_status)
		print_task_status(stdout, target_task);

	/* dump target task VMAs from /proc/PID/maps */
	if (flag_print_vmas)
		dump_task_vmas(target_task, config.verbose);

	/* dump an VMA */
	if (flag_dump_vma)
		dump_task_vma_to_file(output_file, target_task, vma_addr);

	if (flag_dump_addr)
		dump_task_addr_to_file(output_file, target_task, dump_addr,
				       dump_size);

	if (flag_list_symbols)
		list_all_symbol();

	if (flag_print_threads)
		dump_task_threads(target_task, config.verbose);

	if (flag_print_fds)
		dump_task_fds(target_task, config.verbose);

	if (jmp_addr_from && jmp_addr_to) {
		struct vm_area_struct *vma_from, *vma_to;
		vma_from = find_vma(target_task, jmp_addr_from);
		vma_to = find_vma(target_task, jmp_addr_to);
		if (!vma_from || !vma_to) {
			fprintf(stderr,
				"0x%lx ot 0x%lx not in process address space\n"
				"check with /proc/%d/maps or gdb.\n",
				jmp_addr_from, jmp_addr_to, target_pid);
			ret = -1;
			goto done;
		}
		size_t n, insn_sz;
		char *new_insn;
		struct jmp_table_entry jmp_entry;

		jmp_entry.jmp = arch_jmp_table_jmp();
		jmp_entry.addr = jmp_addr_to;
		new_insn = (void *)&jmp_entry;
		insn_sz = sizeof(struct jmp_table_entry);

		n = memcpy_to_task(target_task, jmp_addr_from, new_insn,
					insn_sz);
		if (n == -1 || n < insn_sz) {
			lerror("failed kick target process.\n");
			ret = -1;
			goto done;
		}
	}

	if (disasm_addr && disasm_size) {
		void *mem = malloc(disasm_size);
		ret = memcpy_from_task(target_task, mem, disasm_addr, disasm_size);
		if (ret <= 0) {
			fprintf(stderr, "Bad address 0x%lx\n", disasm_addr);
		} else {
			print_string_hex(stdout, "Hex: ", mem, disasm_size);
			ret = fdisasm_arch(stdout, mem, disasm_size);
			if (ret) {
				fprintf(stderr, "Disasm failed\n");
			}
		}
		free(mem);
	}

done:
	close_task(target_task);
	return ret;
}

