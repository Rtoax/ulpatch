// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include "init.h"
#include "version.h"
#include "elf/elf-api.h"

#include "utils/log.h"
#include "utils/list.h"
#include "utils/util.h"
#include "task/task.h"
#include "utils/disasm.h"
#include "utils/compiler.h"
#include "cmds.h"

#include "patch/patch.h"

#include <args-common.c>


enum {
	ARG_MIN = ARG_COMMON_MAX,
	ARG_JMP,
	ARG_VMAS,
	ARG_DUMP,
	ARG_MAP,
	ARG_MPROTECT,
	ARG_FILE_UNMAP_FROM_VMA,
	ARG_THREADS,
	ARG_FDS,
	ARG_AUXV,
	ARG_STATUS,
	ARG_LIST_SYMBOLS,
};

enum {
	DUMP_VMA_OPTION,
	DUMP_VDSO_OPTION,
	DUMP_DISASM_OPTION,
	DUMP_ADDR_OPTION,
	DUMP_SIZE_OPTION,
	DUMP_END_NULL_OPTION,
};

char *const dump_opts[] = {
	[DUMP_VMA_OPTION] = "vma",
	[DUMP_VDSO_OPTION] = "vdso",
	[DUMP_DISASM_OPTION] = "disasm",
	[DUMP_ADDR_OPTION] = "addr",
	[DUMP_SIZE_OPTION] = "size",
	[DUMP_END_NULL_OPTION] = NULL,
};

enum {
	JMP_FROM_OPTION,
	JMP_TO_OPTION,
	END_JMP_OPTION,
};

char *const jmp_opts[] = {
	[JMP_FROM_OPTION] = "from",
	[JMP_TO_OPTION] = "to",
	[END_JMP_OPTION] = NULL,
};

enum {
	MAP_FILE_OPTION,
	MAP_RO_OPTION,
	MAP_NO_EXEC_OPTION,
	MAP_DUMP_ADDR_OPTION,
	END_MAP_OPTION,
};

char *const map_opts[] = {
	[MAP_FILE_OPTION] = "file",
	[MAP_RO_OPTION] = "ro",
	[MAP_NO_EXEC_OPTION] = "noexec",
	[MAP_DUMP_ADDR_OPTION] = "addr",
	[END_MAP_OPTION] = NULL,
};

enum {
	MPROT_DUMP_ADDR_OPTION,
	MPROT_LEN_OPTION,
	MPROT_NONE_OPTION,
	MPROT_READ_OPTION,
	MPROT_WRITE_OPTION,
	MPROT_EXEC_OPTION,
	END_MPROT_OPTION,
};

char *const mprotect_opts[] = {
	[MPROT_DUMP_ADDR_OPTION] = "addr",
	[MPROT_LEN_OPTION] = "len",
	[MPROT_NONE_OPTION] = "none",
	[MPROT_READ_OPTION] = "read",
	[MPROT_WRITE_OPTION] = "write",
	[MPROT_EXEC_OPTION] = "exec",
	[END_MPROT_OPTION] = NULL,
};

static pid_t target_pid = -1;

static bool flag_print_task = true;
static bool flag_print_vmas = false;
static bool flag_dump_vma = false;
static bool flag_dump_vdso = false;
static bool flag_dump_addr = false;
static bool flag_unmap_vma = false;
static char *map_file = NULL;
static bool map_ro = false;
static bool map_noexec = false;
static unsigned long map_addr = 0;
static unsigned long unmap_addr = 0;
static unsigned long mprotect_addr = 0;
static unsigned long mprotect_len = 0;
static unsigned long mprotect_prot = PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC;
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

static void ultask_args_reset(void)
{
	target_pid = -1;
	flag_print_task = true;
	flag_print_vmas = false;
	flag_dump_vma = false;
	flag_dump_vdso = false;
	flag_dump_addr = false;
	flag_unmap_vma = false;
	map_file = NULL;
	map_ro = false;
	map_noexec = false;
	map_addr = 0;
	unmap_addr = 0;
	mprotect_addr = 0;
	mprotect_len = 0;
	mprotect_prot = PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC;
	vma_addr = 0;
	dump_addr = 0;
	dump_size = 0;
	jmp_addr_from = 0;
	jmp_addr_to = 0;
	flag_list_symbols = false;
	flag_print_threads = false;
	flag_print_fds = false;
	flag_print_auxv = false;
	flag_print_status = false;
	flag_disasm = false;
	disasm_addr = 0;
	disasm_size = 0;
	output_file = NULL;
	flag_rdonly = true;
	target_task = NULL;
}

static int print_help(void)
{
	printf(
	"\n"
	" Usage: ultask [OPTION]... [FILE]...\n"
	"\n"
	" ultask is a process modifier that can modify the memory of a running\n"
	" program, and can also view the process memory and VMA.\n"
	"\n"
	" Essential argument:\n"
	"\n"
	"  -p, --pid [PID]     specify a process identifier(pid_t)\n"
	"\n"
	"  --dump [TYPE,addr=ADDR,size=SIZE]\n"
	"\n"
	"      TYPE=           type of dump.\n"
	"\n"
	"      TYPE=vma\n"
	"                      save VMA address space to console or to a file,\n"
	"                      need to specify address of a VMA. check with -v.\n"
	"                      the input will be take as base 16, default output\n"
	"                      is stdout, write(2), specify output file with -o.\n"
	"      TYPE=vdso\n"
	"                      dump target process's vdso vma to file.\n"
	"\n"
	"      TYPE=disasm\n"
	"                      disassemble a piece of code of target process.\n"
	"\n"
	"  --jmp [from=ADDR,to=ADDR]\n"
	"                      specify a jump entry SRC and DST address\n"
	"                      you better ensure what you are doing.\n"
	"\n"
	"  --map [file=FILE,ro,noexec,addr=ADDR]\n"
	"                      mmap a exist file into target process address space\n"
	"                      option 'ro' means readonly, default rw\n"
	"                      option 'noexec' means no PROT_EXEC, default has it\n"
	"                      option 'addr' specify mmap address\n"
	"\n"
	"  --unmap [=ADDR]     munmap a exist VMA, the argument need input vma address.\n"
	"                      and witch is mmapped by --map.\n"
	"                      check with --vmas and --map.\n"
	"\n"
	"  --mprotect [addr=ADDR,len=SIZE,none,read,write,exec]\n"
	"                      like mprotect(2), set protection on a region of\n"
	"                      target task memory. none=PROT_NONE, read=PROT_READ,\n"
	"                      write=PROT_WRITE,exec=PROT_EXEC\n"
	"\n"
	"  --vmas              dump vmas\n"
	"  --threads           dump threads\n"
	"  --fds               dump fds\n"
	"  --auxv              print auxv\n"
	"  --status            print status\n"
	"  --syms, --symbols   list all symbols\n"
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
	cmd_exit_success();
	return 0;
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
		{ "dump",           required_argument, 0, ARG_DUMP },
		{ "jmp",            required_argument, 0, ARG_JMP },
		{ "map",            required_argument, 0, ARG_MAP },
		{ "mprotect",       required_argument, 0, ARG_MPROTECT },
		{ "unmap",          required_argument, 0, ARG_FILE_UNMAP_FROM_VMA },
		{ "symbols",        no_argument,       0, ARG_LIST_SYMBOLS },
		{ "syms",           no_argument,       0, ARG_LIST_SYMBOLS },
		{ "output",         required_argument, 0, 'o' },
		COMMON_OPTIONS
		{ NULL }
	};

	while (1) {
		int c;
		int option_index = 0;
		char *subopts, *value;

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
		case ARG_DUMP:
			subopts = optarg;
			while (*subopts != '\0') {
				switch (getsubopt(&subopts, dump_opts, &value)) {
				case DUMP_VMA_OPTION:
					flag_dump_vma = true;
					break;
				case DUMP_VDSO_OPTION:
					flag_dump_vdso = true;
					break;
				case DUMP_DISASM_OPTION:
					flag_disasm = true;
					break;
				case DUMP_ADDR_OPTION:
					dump_addr = str2addr(value);
					break;
				case DUMP_SIZE_OPTION:
					dump_size = str2size(value);
					break;
				default:
					fprintf(stderr, "unknown option %s of --dump\n", value);
					cmd_exit(1);
					break;
				}
			}

			if ((flag_dump_vma || flag_dump_vdso) && flag_disasm) {
				fprintf(stderr, "only vma or disasm.\n");
				cmd_exit(1);
			} else if (flag_dump_vma && flag_dump_vdso) {
				fprintf(stderr, "only vma or vdso.\n");
				cmd_exit(1);
			} else if (flag_dump_vma) {
				if (dump_addr == 0) {
					fprintf(stderr, "dump vma need addr=.\n");
					cmd_exit(1);
				}
				vma_addr = dump_addr;
			} else if (flag_disasm) {
				if (dump_addr == 0 || dump_size == 0) {
					fprintf(stderr, "disasm need addr= and size=\n");
					cmd_exit(1);
				}
				disasm_addr = dump_addr;
				disasm_size = dump_size;
			} else if (flag_dump_vdso) {
				/* no need other argument */
				if (dump_addr != 0 || dump_size != 0) {
					fprintf(stderr, "dump vdso no need addr and size\n");
					cmd_exit(1);
				}
				dump_addr = 0;
			} else {
				if (dump_addr == 0 || dump_size == 0) {
					fprintf(stderr, "dump memory need addr= and size=\n");
					cmd_exit(1);
				}
				flag_dump_addr = true;
			}
			break;
		case ARG_JMP:
			subopts = optarg;
			while (*subopts != '\0') {
				switch (getsubopt(&subopts, jmp_opts, &value)) {
				case JMP_FROM_OPTION:
					jmp_addr_from = str2addr(value);
					break;
				case JMP_TO_OPTION:
					jmp_addr_to = str2addr(value);
					break;
				default:
					fprintf(stderr, "unknown option %s of --jmp\n", value);
					cmd_exit(1);
					break;
				}
			}
			flag_rdonly = false;
			if (jmp_addr_from == 0 || jmp_addr_to == 0) {
				fprintf(stderr, "jmp need from= and to=\n");
				cmd_exit(1);
			}
			break;
		case ARG_MAP:
			subopts = optarg;
			while (*subopts != '\0') {
				switch (getsubopt(&subopts, map_opts, &value)) {
				case MAP_FILE_OPTION:
					map_file = value;
					break;
				case MAP_RO_OPTION:
					map_ro = true;
					break;
				case MAP_NO_EXEC_OPTION:
					map_noexec = true;
					break;
				case MAP_DUMP_ADDR_OPTION:
					map_addr = str2addr(value);
					if (map_addr == 0) {
						fprintf(stderr, "invalid map addr.\n");
						cmd_exit(EINVAL);
					}
					break;
				default:
					fprintf(stderr, "unknown option %s of --map\n", value);
					cmd_exit(1);
					break;
				}
			}
			flag_rdonly = false;
			if (!map_file) {
				fprintf(stderr, "map need file=\n");
				cmd_exit(1);
			}
			break;
		case ARG_FILE_UNMAP_FROM_VMA:
			flag_unmap_vma = true;
			flag_rdonly = false;
			unmap_addr = str2addr(optarg);
			break;
		case ARG_MPROTECT:
			subopts = optarg;
			mprotect_prot = PROT_NONE;
			bool flag_prot_none = false;
			while (*subopts != '\0') {
				switch (getsubopt(&subopts, mprotect_opts,
					&value)) {
				case MPROT_DUMP_ADDR_OPTION:
					mprotect_addr = str2addr(value);
					break;
				case MPROT_LEN_OPTION:
					mprotect_len = str2addr(value);
					break;
				case MPROT_NONE_OPTION:
					flag_prot_none = true;
					break;
				case MPROT_READ_OPTION:
					mprotect_prot |= PROT_READ;
					break;
				case MPROT_WRITE_OPTION:
					mprotect_prot |= PROT_WRITE;
					break;
				case MPROT_EXEC_OPTION:
					mprotect_prot |= PROT_EXEC;
					break;
				default:
					fprintf(stderr, "unknown option %s of --mprotect\n", value);
					cmd_exit(1);
					break;
				}
			}
			if (flag_prot_none && mprotect_prot != PROT_NONE) {
				fprintf(stderr, "mprotect: can't set none and read|write|exec at the same time.\n");
				cmd_exit(EINVAL);
			}
			flag_rdonly = false;
			if (!mprotect_addr || !mprotect_len) {
				fprintf(stderr, "--mprotect addr or len error\n");
				cmd_exit(1);
			}
			/**
			 * mprotect(2) addr must be aligned to a page boundary.
			 * mprotect(2) will automatically handle page alignment
			 * of the LEN parameter, but we still check here.
			 */
			if ((mprotect_addr % ulp_page_size()) ||
			    (mprotect_len % ulp_page_size())) {
				fprintf(stderr, "mprotect must align page 0x%x\n",
					ulp_page_size());
				cmd_exit(1);
			}
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
		case 'o':
			output_file = optarg;
			break;
		COMMON_GETOPT_CASES(prog_name, print_help, argv)
		default:
			print_help();
			cmd_exit(1);
			break;
		}
	}

	/**
	 * It is necessary to specify a valid process ID.
	 */
	if (target_pid == -1) {
		fprintf(stderr, "Specify pid with -p, --pid.\n");
		cmd_exit(1);
	}

	if (!proc_pid_exist(target_pid)) {
		fprintf(stderr, "pid %d not exist.\n", target_pid);
		cmd_exit(1);
	}

	/**
	 * There needs to be one action, or more than one action.
	 */
	if (!flag_print_vmas &&
		!flag_dump_vma &&
		!flag_dump_vdso &&
		!flag_dump_addr &&
		!map_file &&
		!mprotect_addr &&
		(!jmp_addr_from || !jmp_addr_to) &&
		!flag_unmap_vma &&
		!flag_list_symbols &&
		!flag_print_auxv &&
		!flag_print_status &&
		!flag_print_threads &&
		!flag_disasm &&
		!flag_print_fds)
	{
		fprintf(stderr, "nothing to do, -h, --help.\n");
	} else {
		/**
		 * If no command line arguments are specified, some task
		 * information will be printed by default, but if command line
		 * arguments are specified, it will not be printed.
		 */
		flag_print_task = false;
	}

	if ((flag_dump_vma || flag_dump_vdso) && !output_file) {
		fprintf(stderr, "--dump vma|vdso need output file(-o).\n");
		cmd_exit(1);
	}

	if (flag_dump_addr && !output_file) {
		fprintf(stderr, "--dump need output file(-o).\n");
		cmd_exit(1);
	}

	if (map_file) {
		const char *real_map_file = NULL;
		char cwd_file[PATH_MAX];

		/* Absolute path */
		if (map_file[0] == '/') {
			if (!fexist(map_file)) {
				fprintf(stderr, "%s is not exist.\n", map_file);
				cmd_exit(EEXIST);
			}
			real_map_file = map_file;

		/* Otherwise, file must in target process cwd. */
		} else {
			char buf_tcwd[PATH_MAX];
			const char *tcwd;

			tcwd = proc_pid_cwd(target_pid, buf_tcwd,
				sizeof(buf_tcwd));

			snprintf(cwd_file, PATH_MAX, "%s/%s", tcwd, map_file);
			if (!fexist(cwd_file)) {
				fprintf(stderr, "%s is not exist under target cwd %s.\n",
					map_file, tcwd);
				cmd_exit(EEXIST);
			}
			real_map_file = cwd_file;
		}

		if (!fregular(real_map_file)) {
			fprintf(stderr, "%s is not regular file.\n",
				real_map_file);
			cmd_exit(ENOENT);
		}

		/**
		 * Although mmap(2) will fail for an empty file, I still want
		 * to determine whether it is an empty file in advance. If it
		 * is an empty file, I can directly report an error when
		 * testing ultask(). After all, an empty file is also an
		 * illegal input.
		 */
		if (fsize(real_map_file) == 0) {
			fprintf(stderr, "%s is empty.\n", real_map_file);
			cmd_exit(EINVAL);
		}

		map_file = malloc(PATH_MAX);

		strcpy(map_file, real_map_file);
	}

	if (output_file && !force && fexist(output_file)) {
		fprintf(stderr, "%s is already exist.\n", output_file);
		cmd_exit(1);
	}

	return 0;
}

static int mmap_a_file(void)
{
	int ret = 0;
	ssize_t map_len = fsize(map_file);
	unsigned long map_v;
	int map_fd;
	const char *filename = map_file;
	int prot;
	unsigned long addr = 0UL;

	struct task_struct *task = target_task;

	/**
	 * Check address first, if map_addr is invalid, just return instead of
	 * attach task.
	 *
	 * NOTE: map_addr equal to 0 also is a valid value.
	 */
	if (map_addr) {
		if (find_vma(task, map_addr) ||
		    find_vma(task, map_addr + map_len))
		{
			fprintf(stderr, "address 0x%lx already in use.\n",
				map_addr);
			return -EINVAL;
		}
		addr = map_addr;
	}

	ret = task_attach(task->pid);
	if (ret)
		return ret;

	map_fd = task_open2(task, (char *)filename, O_RDWR);
	if (map_fd <= 0) {
		fprintf(stderr, "ERROR: remote open failed.\n");
		return -1;
	}

	ret = task_ftruncate(task, map_fd, map_len);
	if (ret != 0) {
		fprintf(stderr, "ERROR: remote ftruncate failed.\n");
		goto close_ret;
	}

	prot = PROT_READ | PROT_WRITE | PROT_EXEC;

	if (map_ro)
		prot &= ~PROT_WRITE;

	if (map_noexec)
		prot &= ~PROT_EXEC;

	map_v = task_mmap(task, addr, map_len, prot, MAP_PRIVATE, map_fd, 0);
	if (!map_v) {
		fprintf(stderr, "ERROR: remote mmap failed.\n");
		goto close_ret;
	}

close_ret:
	task_close(task, map_fd);
	task_detach(task->pid);

	update_task_vmas_ulp(task);

	return ret;
}

static int mprotect_a_region(void)
{
	int ret = 0;
	struct task_struct *task = target_task;

	/**
	 * Check address first, if address is invalid, just return instead of
	 * attach task.
	 */
	if (!mprotect_addr || !mprotect_len)
		return -EINVAL;

	if (!find_vma(task, mprotect_addr) ||
	    !find_vma(task, mprotect_addr + mprotect_len))
	{
		fprintf(stderr, "address 0x%lx-0x%lx not exist.\n",
			mprotect_addr, mprotect_addr + mprotect_len);
		return -EINVAL;
	}

	ret = task_attach(task->pid);
	if (ret)
		return ret;

	ret = task_mprotect(task, mprotect_addr, mprotect_len, mprotect_prot);
	if (ret)
		fprintf(stderr, "ERROR: remote mprotect failed.\n");

	task_detach(task->pid);
	return ret;
}

static int munmap_an_vma(void)
{
	int err = 0;
	size_t size = 0;
	struct task_struct *task = target_task;
	unsigned long addr = 0;

	struct vm_area_struct *vma = find_vma(task, unmap_addr);
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

	err = task_attach(task->pid);
	if (err)
		return err;
	task_munmap(task, addr, size);
	task_detach(task->pid);

	return 0;
}

static void list_all_symbols(void)
{
	int max_name_len = 0, max_vma_len = 0;
	struct task_sym *tsym;
	struct task_struct *task = target_task;

	for (tsym = next_task_sym(task, NULL); tsym;
	     tsym = next_task_sym(task, tsym))
	{
		int len = strlen(tsym->name);
		if (max_name_len < len)
			max_name_len = len;
		len = strlen(basename(tsym->vma->name_));
		if (max_vma_len < len)
			max_vma_len = len;
	}

	for (tsym = next_task_sym(task, NULL); tsym;
	     tsym = next_task_sym(task, tsym))
	{
#define PRINT_TSYM(tasksym)	\
		printf("%-*s %-*s %#016lx\n",	\
			max_vma_len, basename(tasksym->vma->name_),	\
			max_name_len, tasksym->name,	\
			tasksym->addr);
		PRINT_TSYM(tsym);

		/**
		 * If verbose, print symbol detail, there could more than one
		 * addresses of one symbol.
		 */
		if (is_verbose()) {
			struct task_sym *is, *tmp;
			list_for_each_entry_safe(is, tmp,
			    &tsym->list_name.head, list_name.node) {
				PRINT_TSYM(is);
			}
		}
#undef PRINT_TSYM
	}
}

int run_jmp(void)
{
	int err = 0;
	struct vm_area_struct *vma_from, *vma_to;
	size_t n, insn_sz;
	char *new_insn;
	struct jmp_table_entry jmp_entry;
	char buf[sizeof(struct jmp_table_entry)] = {};

	if (!jmp_addr_from || !jmp_addr_to)
		return 0;

	vma_from = find_vma(target_task, jmp_addr_from);
	vma_to = find_vma(target_task, jmp_addr_to);
	if (!vma_from || !vma_to) {
		fprintf(stderr,
			"0x%lx ot 0x%lx not in process address space\n"
			"check with /proc/%d/maps or gdb.\n",
			jmp_addr_from, jmp_addr_to, target_pid);
		err = -ENOENT;
		goto done;
	}

	jmp_entry.jmp = arch_jmp_table_jmp();
	jmp_entry.addr = jmp_addr_to;
	new_insn = (void *)&jmp_entry;
	insn_sz = sizeof(struct jmp_table_entry);

	n = memcpy_from_task(target_task, buf, jmp_addr_from, insn_sz);
	if (n == -1 || n < insn_sz) {
		ulp_error("failed read target process.\n");
		err = -ENOMEM;
		goto done;
	}

	/**
	 * Display original data, disasm too, however, if the data is not in
	 * code(.text) section, it's means nothing.
	 */
	fprintf(stdout, "OrigBytes:  ");
	fmembytes(stdout, buf, insn_sz);
	fdisasm_arch(stdout, "OrigBytes:  ", jmp_addr_from,
		     (unsigned char *)buf, insn_sz);

	/* Display new data */
	fprintf(stdout, "WroteBytes: ");
	fmembytes(stdout, new_insn, insn_sz);
	fdisasm_arch(stdout, "WroteBytes: ", jmp_addr_from,
		     (unsigned char *)new_insn, insn_sz);

	n = memcpy_to_task(target_task, jmp_addr_from, new_insn,
				insn_sz);
	if (n == -1 || n < insn_sz) {
		ulp_error("failed kick target process.\n");
		err = -ENOMEM;
		goto done;
	}
done:
	return err;
}

int run_disasm(void)
{
	void *mem;
	int ret = 0;

	if (!disasm_addr || !disasm_size)
		return 0;

	mem = malloc(disasm_size);

	ret = memcpy_from_task(target_task, mem, disasm_addr, disasm_size);
	if (ret <= 0) {
		fprintf(stderr, "Bad address 0x%lx\n", disasm_addr);
		ret = -ENOMEM;
		goto done;
	}

	print_string_hex(stdout, "Hex: ", mem, disasm_size);
	ret = fdisasm_arch(stdout, NULL, 0, mem, disasm_size);
	if (ret) {
		fprintf(stderr, "Disasm failed\n");
	}

done:
	free(mem);
	return ret;
}

int ultask(int argc, char *argv[])
{
	int ret = 0;
	int flags = FTO_ALL;

	COMMON_RESET_BEFORE_PARSE_ARGS(ultask_args_reset);

	ret = parse_config(argc, argv);
#if !defined(ULP_CMD_MAIN)
	if (ret == CMD_RETURN_SUCCESS_VALUE)
		return 0;
#endif
	if (ret)
		return ret;

	COMMON_IN_MAIN_AFTER_PARSE_ARGS();

	ulpatch_init();

	if (flag_rdonly)
		flags &= ~FTO_RDWR;

	target_task = open_task(target_pid, flags);
	if (!target_task) {
		fprintf(stderr, "open pid %d failed. %m\n", target_pid);
		return 1;
	}

	if (flag_print_task)
		print_task(stdout, target_task, is_verbose());

	if (mprotect_addr)
		ret += mprotect_a_region();

	if (map_file)
		ret += mmap_a_file();

	if (flag_unmap_vma)
		ret += munmap_an_vma();

	if (flag_print_auxv)
		print_task_auxv(stdout, target_task);

	if (flag_print_status)
		print_task_status(stdout, target_task);

	/* dump target task VMAs from /proc/PID/maps */
	if (flag_print_vmas)
		dump_task_vmas(stdout, target_task, is_verbose());

	/* dump an VMA */
	if (flag_dump_vma)
		dump_task_vma_to_file(output_file, target_task, vma_addr);

	if (flag_dump_vdso) {
		struct vm_area_struct *vma = task_vdso_vma(target_task);
		dump_task_vma_to_file(output_file, target_task, vma->vm_start + 1);
	}

	if (flag_dump_addr)
		dump_task_addr_to_file(output_file, target_task, dump_addr,
				       dump_size);

	if (flag_list_symbols)
		list_all_symbols();

	if (flag_print_threads)
		dump_task_threads(stdout, target_task, is_verbose());

	if (flag_print_fds)
		dump_task_fds(stdout, target_task, is_verbose());

	run_jmp();
	run_disasm();

	close_task(target_task);
	return ret;
}

#if defined(ULP_CMD_MAIN)
int main(int argc, char *argv[])
{
	return ultask(argc, argv);
}
#endif
