
struct config config = {
	.log_level = LOG_ERR,
	.verbose = 0,
};

enum {
	ARG_LOG_LEVEL = 139,
	ARG_LOG_DEBUG,
	ARG_LOG_ERR,
	ARG_COMMON_MAX,
};

void print_usage_common(const char *progname)
{
	printf(
	" Common argument:\n"
	"\n"
	"  --log-level [NUM]   set log level, default(%d)\n"
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
	"  -v, --verbose       set verbose\n"
	"  -h, --help          display this help and exit\n"
	"  -V, --version       output version information and exit\n"
	"\n");
	printf(" %s %s\n", progname, ulpatch_version());
}

#define COMMON_OPTIONS	\
	{ "version",        no_argument,       0, 'V' },	\
	{ "help",           no_argument,       0, 'h' },	\
	{ "log-level",      required_argument, 0, ARG_LOG_LEVEL },	\
	{ "log-debug",      no_argument,       0, ARG_LOG_DEBUG },	\
	{ "log-error",      no_argument,       0, ARG_LOG_ERR },	\
	{ "verbose",        no_argument,       0, 'v' },
#define COMMON_GETOPT_OPTSTRING "Vvh"

#define COMMON_GETOPT_CASES(progname, usage)	\
	case 'V':	\
		printf("%s %s\n", progname, ulpatch_version());	\
		exit(0);	\
	case 'h':	\
		usage();	\
		exit(0);	\
		break;	\
	case 'v':	\
		config.verbose = true;	\
		set_log_prefix(true);	\
		break;	\
	case ARG_LOG_LEVEL:	\
		config.log_level = atoi(optarg);	\
		break;	\
	case ARG_LOG_DEBUG:	\
		config.log_level = LOG_DEBUG;	\
		break;	\
	case ARG_LOG_ERR:	\
		config.log_level = LOG_ERR;	\
		break;	\
	case '?':	\
		fprintf(stderr, "Unknown option or option missing argument.\n");	\
		exit(1);

