
struct config config = {
	.log_level = LOG_ERR,
	.verbose = 0,
};

enum {
	ARG_LOG_LEVEL = 139,
	ARG_LOG_DEBUG,
	ARG_LOG_ERR,
	ARG_LOG_PREFIX_OFF,
	ARG_COMMON_MAX,
};

void print_usage_common(const char *progname)
{
	printf(
	" Common argument:\n"
	"\n"
	"  --log-level         set log level, default(%d)\n"
	"                      EMERG(%d),ALERT(%d),CRIT(%d),ERR(%d),WARN(%d)\n"
	"                      NOTICE(%d),INFO(%d),DEBUG(%d)\n"
	"  --log-debug         set log level to DEBUG(%d)\n"
	"  --log-error         set log level to ERR(%d)\n"
	"  --log-prefix-off    turn log prefix off. default is open\n"
	"\n",
	config.log_level,
	LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO,
	LOG_DEBUG,
	LOG_DEBUG,
	LOG_ERR);
	printf(
	"  -V, --verbose       set verbose\n"
	"  -h, --help          display this help and exit\n"
	"  -v, --version       output version information and exit\n"
	"\n");
	printf(" %s %s\n", progname, ulpatch_version());
}

#define COMMON_OPTIONS	\
	{ "version",        no_argument,       0, 'v' },	\
	{ "help",           no_argument,       0, 'h' },	\
	{ "log-level",      required_argument, 0, ARG_LOG_LEVEL },	\
	{ "log-debug",      no_argument,       0, ARG_LOG_DEBUG },	\
	{ "log-error",      no_argument,       0, ARG_LOG_ERR },	\
	{ "log-prefix-off", no_argument,       0,  ARG_LOG_PREFIX_OFF }, \
	{ "verbose",        no_argument,       0, 'V' },
#define COMMON_GETOPT_OPTSTRING "Vvh"

#define COMMON_GETOPT_CASES(progname)	\
	case 'v':	\
		printf("%s %s\n", progname, ulpatch_version());	\
		exit(0);	\
	case 'h':	\
		print_help();	\
		break;	\
	case 'V':	\
		config.verbose = true;	\
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
	case ARG_LOG_PREFIX_OFF:	\
		set_log_prefix(false);	\
		break;

