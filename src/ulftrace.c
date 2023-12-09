// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

#include <elf/elf_api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>
#include <utils/task.h>

#include <patch/patch.h>


struct config config = {
	.log_level = LOG_ERR,
};

enum {
	ARG_LOG_LEVEL = 139,
	ARG_LOG_DEBUG,
	ARG_LOG_ERR,
};

static pid_t target_pid = -1;
static const char *target_func = NULL;
static struct task *target_task = NULL;

static const char *patch_object_file = NULL;

/* This is ftrace object file path, during 'make install' install to
 * /usr/share/ulpatch/, this macro is a absolute path of LSB relocatable file.
 *
 * see top level of CMakeLists.txt
 */
#if !defined(ULPATCH_FTRACE_OBJ_PATH)
# error "Need ULPATCH_FTRACE_OBJ_PATH"
#endif

static const char *prog_name = "ulftrace";


static void print_help(void)
{
	printf(
	"\n"
	" Usage: ulftrace [OPTION]... [FILE]...\n"
	"\n"
	" User space ftrace\n"
	"\n"
	" Mandatory arguments to long options are mandatory for short options too.\n"
	"\n"
	" Base argument:\n"
	"\n"
	"  -p, --pid           specify a process identifier(pid_t)\n"
	"\n"
	"\n"
	" Ftrace argument:\n"
	"\n"
	"  -f, --function      tracing funtion specified by this argument.\n"
	"\n"
	"  -j, --patch-obj     input a ELF 64-bit LSB relocatable object file.\n"
	"                      actually, this input is not necessary, unless you know\n"
	"                      how to generate a ftrace relocatable object.\n"
	"                      default: %s\n"
	"\n",
	ULPATCH_FTRACE_OBJ_PATH);
	printf(
	" Common argument:\n"
	"\n"
	"  --log-level         set log level, default(%d)\n"
	"                      EMERG(%d),ALERT(%d),CRIT(%d),ERR(%d),WARN(%d)\n"
	"                      NOTICE(%d),INFO(%d),DEBUG(%d)\n"
	"  --log-debug         set log level to DEBUG(%d)\n"
	"  --log-error         set log level to ERR(%d)\n"
	"\n",
	config.log_level,
	LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO,
	LOG_DEBUG,
	LOG_DEBUG,
	LOG_ERR);
	printf(
	"  -h, --help          display this help and exit\n"
	"  -v, --version       output version information and exit\n"
	"\n");
	printf(
	" ulftrace %s\n",
	ulpatch_version());
	exit(0);
}

static int parse_config(int argc, char *argv[])
{
	struct option options[] = {
		{ "pid",            required_argument,  0, 'p' },
		{ "function",       required_argument,  0, 'f' },
		{ "patch-obj",      required_argument,  0, 'j' },
		{ "version",        no_argument,        0, 'v' },
		{ "help",           no_argument,        0, 'h' },
		{ "log-level",      required_argument,  0, ARG_LOG_LEVEL },
		{ "log-debug",      no_argument,        0, ARG_LOG_DEBUG },
		{ "log-error",      no_argument,        0, ARG_LOG_ERR },
		{ NULL }
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "p:f:j:vh", options, &option_index);
		if (c < 0) {
			break;
		}
		switch (c) {
		case 'p':
			target_pid = atoi(optarg);
			break;
		case 'f':
			target_func = optarg;
			break;
		case 'j':
			patch_object_file = optarg;
			break;
		case 'v':
			printf("%s %s\n", prog_name, ulpatch_version());
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

	if (target_pid == -1) {
		fprintf(stderr, "Specify pid with -p, --pid.\n");
		exit(1);
	}

	if (!target_func) {
		fprintf(stderr, "Specify target function to trace with -f, --function.\n");
		exit(1);
	}

	if (!proc_pid_exist(target_pid)) {
		fprintf(stderr, "pid %d not exist.\n", target_pid);
		exit(1);
	}

	if (patch_object_file && !fexist(patch_object_file)) {
		fprintf(stderr, "%s not exist.\n", patch_object_file);
		exit(1);
	}

	if (!patch_object_file) {
		if (!fexist(ULPATCH_FTRACE_OBJ_PATH)) {
			fprintf(stderr,
				"Default ftrace relocatable object %s is not exist.\n"
				"Make sure you install ulpatch correctly.\n",
				ULPATCH_FTRACE_OBJ_PATH
			);
			exit(1);
		}
		fprintf(stderr, "WARNING: use default %s.\n",
			ULPATCH_FTRACE_OBJ_PATH);
		patch_object_file = ULPATCH_FTRACE_OBJ_PATH;
	}

	if (!fexist(patch_object_file)) {
		fprintf(stderr, "%s is not exist.\n", patch_object_file);
		exit(1);
	}

	if ((ftype(patch_object_file) & FILE_ELF_RELO) != FILE_ELF_RELO) {
		fprintf(stderr, "%s is not ELF or ELF LSB relocatable.\n",
			patch_object_file);
		exit(1);
	}

	return 0;
}


int main(int argc, char *argv[])
{
	int __unused ret = 0;
	struct symbol *target_sym;

	parse_config(argc, argv);

	ulpatch_env_init();

	set_log_level(config.log_level);

	target_task = open_task(target_pid, FTO_ULFTRACE);
	if (!target_task) {
		fprintf(stderr, "open %d failed. %s\n", target_pid, strerror(errno));
		return 1;
	}

	target_sym = task_vma_find_symbol(target_task, target_func);
	if (!target_sym) {
		fprintf(stderr, "couldn't found symbol '%s'\n", target_func);
		errno = -ENOENT;
		ret = 1;
		goto done;
	}

	init_patch(target_task, ULPATCH_FTRACE_OBJ_PATH);

	// MORE

	delete_patch(target_task);

done:
	free_task(target_task);

	return ret;
}

