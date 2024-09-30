// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */

/**
 * This source code file is included (#include) into other source code, which
 * is compiled into an executable file that parses the command line arguments
 * by requiring the execution of getopt/getopt_long.
 */

static int log_level = LOG_ERR;
static bool force = false;

enum {
	ARG_LOG_LEVEL = 139,
	ARG_LOG_DEBUG,
	ARG_LOG_ERR,
	ARG_LOG_INFO,
	ARG_COMMON_MAX,
};

static void args_common_reset(void)
{
	reset_verbose();
	log_level = LOG_ERR;
	force = false;
}

static void reset_getopt(void)
{
	optarg = NULL;
	optind = opterr = optopt = 0;
}

static void print_usage_common(const char *progname)
{
	printf(
	" Common argument:\n"
	"\n"
	"  --log-level [NUM|STR]\n"
	"  --lv [NUM|STR]      set log level, default(%d)\n"
	"                      EMERG(%d),ALERT(%d),CRIT(%d),ERR(%d),WARN(%d)\n"
	"                      NOTICE(%d),INFO(%d),DEBUG(%d)\n"
	"                      or %s\n"
	"  --log-debug         set log level to DEBUG(%d)\n"
	"  --log-error         set log level to ERR(%d)\n"
	"\n",
	get_log_level(),
	LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO,
	LOG_DEBUG, log_level_list(),
	LOG_DEBUG,
	LOG_ERR);
	printf(
	"  -u, --dry-run       don’t actually run\n"
	"  -v[v...], --verbose set verbose, more v specified, more detail to display.\n"
	"  -h, --help          display this help and exit\n"
	"  -V, --version       output version information and exit\n"
	"  -F, --force         force, such as overwirte exist file\n"
	"  --info              Print detailed information about features \n"
	"                      supported by the kernel and the ulpatch build.\n"
	"\n");
	printf(" %s %s\n", progname, ulpatch_version());
}

#define COMMON_OPTIONS	\
	{ "version",        no_argument,       0, 'V' },	\
	{ "help",           no_argument,       0, 'h' },	\
	{ "log-level",      required_argument, 0, ARG_LOG_LEVEL },	\
	{ "lv",             required_argument, 0, ARG_LOG_LEVEL },	\
	{ "log-debug",      no_argument,       0, ARG_LOG_DEBUG },	\
	{ "log-error",      no_argument,       0, ARG_LOG_ERR },	\
	{ "dry-run",        no_argument,       0, 'u' },	\
	{ "verbose",        no_argument,       0, 'v' },	\
	{ "info",           no_argument,       0, ARG_LOG_INFO },	\
	{ "force",          no_argument,       0, 'F' },
#define COMMON_GETOPT_OPTSTRING "uVv::hF"

#define COMMON_GETOPT_CASES(progname, usage, argv)	\
	case 'V':	\
		printf("%s %s\n", progname, ulpatch_version());	\
		cmd_exit_success();	\
	case 'h':	\
		usage();	\
		cmd_exit_success();	\
		break;	\
	case 'v':	\
		enable_verbose(str2verbose(optarg) + 1);	\
		set_log_prefix(true);	\
		break;	\
	case 'u':	\
		enable_dry_run();	\
		break;	\
	case ARG_LOG_LEVEL:	\
		log_level = atoi(optarg);	\
		if (!log_level)	\
			log_level = str2loglevel(optarg);	\
		break;	\
	case ARG_LOG_DEBUG:	\
		log_level = LOG_DEBUG;	\
		break;	\
	case ARG_LOG_ERR:	\
		log_level = LOG_ERR;	\
		break;	\
	case ARG_LOG_INFO:	\
		ulpatch_info(progname);	\
		cmd_exit_success();	\
	case 'F':	\
		force = true;	\
		break;	\
	case '?':	\
		fprintf(stderr, "ERROR: Unknown option or %s missing argument.\n", argv[optind - 1]);	\
		cmd_exit(1);

#define COMMON_RESET(cmd_args_reset_fn) do {	\
		cmd_args_reset_fn();	\
		args_common_reset();	\
		reset_getopt();	\
	} while (0)

#define COMMON_IN_MAIN() do {	\
		set_log_level(log_level);	\
	} while (0)

