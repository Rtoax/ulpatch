// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>
#include <task/task.h>
#include <utils/cmds.h>
#include <elf/elf-api.h>
#include <tests/test-api.h>

/* Must between utils/cmds.h and args-common.c */
#undef cmd_exit_success
#define cmd_exit_success() exit(0)
#undef cmd_exit
#define cmd_exit(v) exit(v)

#include <args-common.c>


struct list_head test_list[TEST_PRIO_NUM];
static LIST_HEAD(failed_list);

static LIST_HEAD(mix_role_list);

/* ulpatch_test always single-thread, thus, current is safety. */
struct test *current_test = NULL;

int main(int argc, char *argv[]);

static void __ctor(TEST_PRIO_START) __init_test_list(void)
{
	int i;
	for (i = 0; i < TEST_PRIO_NUM; i++) {
		list_init(&test_list[i]);
	}
}

#define test_log(fmt...) ({	\
		int __n = 0;	\
		__n = fprintf(stderr, fmt);	\
		__n;	\
	})

#define test_ok(fmt...) do {	\
		fprintf(stderr, "\033[32m");	\
		fprintf(stderr, fmt);	\
		fprintf(stderr, "\033[m");	\
	} while (0)

#define test_failed(fmt...) do {	\
		fprintf(stderr, "\033[31m");	\
		fprintf(stderr, fmt);	\
		fprintf(stderr, "\033[m");	\
	} while (0)


#define STAT_IDX_SUCCESS	0
#define STAT_IDX_FAILED		1
static unsigned long stat_count[2] = {0};

static unsigned long total_spent_us = 0;

/* For -l, --list-tests */
static bool just_list_tests = false;
/* For -f, --filter or --skip */
struct filter_fmt {
	const char *fmt;
	bool skip;
	struct list_head node; /* head is filter_fmt_list */
};
static LIST_HEAD(filter_fmt_list);

/* exit if Error */
static bool error_exit = false;

/* set number of thread of ROLE_MULTI_THREADS */
static int nr_threads = 3;

/* For -r, --role */
static enum who {
	ROLE_NONE,
	ROLE_TESTER, // testing all Tests
	ROLE_SLEEPER, // be tested
	ROLE_WAITING, // wait for a while
	ROLE_TRIGGER, // trigger
	ROLE_PRINTER, // printer
	ROLE_MULTI_THREADS, // multi-threads
	ROLE_LISTENER, // listener
	ROLE_MIX, // mix: sleeper, waiting, trigger
	ROLE_MAX,
} role = ROLE_TESTER;

static const char *role_string[ROLE_MAX] = {
	[ROLE_NONE] = "none",
	[ROLE_TESTER] = "tester",
	[ROLE_SLEEPER] = "sleeper",
	[ROLE_WAITING] = "wait",
	[ROLE_TRIGGER] = "trigger",
	[ROLE_PRINTER] = "printer",
	[ROLE_MULTI_THREADS] = "multi-threads",
	[ROLE_LISTENER] = "listener",
	[ROLE_MIX] = "mix",
};

static int sleep_usec = 100;
static char *msgq_file = NULL;

#define PRINT_INTERVAL_USEC	10000
#define PRINT_NLOOP	10

static int print_interval_usec = PRINT_INTERVAL_USEC;
static int print_nloop_default = PRINT_NLOOP;
const char *print_content = "Hello";

const char *ulpatch_test_path = NULL;

const char *listener_request = NULL;
static bool listener_request_list = false;
static int listener_nloop = 1;
static bool listener_epoll = false;

static void print_test_symbol(void);

static const char *prog_name = "ulpatch_test";


static void add_filter_fmt(const char *str, bool skip)
{
	struct filter_fmt *fmt;
	fmt = malloc(sizeof(struct filter_fmt));
	fmt->fmt = strdup(str);
	fmt->skip = skip;
	ulp_debug("Alloc filter %s, skip %d\n", str, skip);
	list_add(&fmt->node, &filter_fmt_list);
}

static inline int has_filter(void)
{
	return !list_empty(&filter_fmt_list);
}

static inline int has_filter_match(void)
{
	struct filter_fmt *fmt;
	list_for_each_entry(fmt, &filter_fmt_list, node)
		if (!fmt->skip)
			return true;
	return false;
}

static inline int has_filter_skip(void)
{
	struct filter_fmt *fmt;
	list_for_each_entry(fmt, &filter_fmt_list, node)
		if (fmt->skip)
			return true;
	return false;
}

static int filter_matched(const char *category_name)
{
	struct filter_fmt *fmt;
	list_for_each_entry(fmt, &filter_fmt_list, node)
		if (strstr(category_name, fmt->fmt) && !fmt->skip)
			return true;
	return false;
}

static inline int filter_matched_skip(const char *category_name)
{
	struct filter_fmt *fmt;
	list_for_each_entry(fmt, &filter_fmt_list, node)
		if (strstr(category_name, fmt->fmt) && fmt->skip)
			return true;
	return false;
}

static void free_filter_fmt_list(void)
{
	struct filter_fmt *fmt, *tmp;
	list_for_each_entry_safe(fmt, tmp, &filter_fmt_list, node) {
		free((void *)fmt->fmt);
		free(fmt);
	}
}

static enum who who_am_i(const char *s)
{
	int i;

	for (i = ROLE_TESTER; i < ARRAY_SIZE(role_string); i++) {
		if (!strcmp(s, role_string[i])) {
			/* Not allow set ROLE_MIX directly */
			return i != ROLE_MIX ? i : ROLE_NONE;
		}
	}

	/* Not one of ROLE_XXX, maybe is ROLE_MIX, that is to say
	 * -r, --role is sleeper,wait,trigger mixed
	 */
	if (strstr(s, ",")) {
		struct str_node *str = NULL, *tmp;
		parse_strstr((char *)s, &mix_role_list);

		strstr_for_each_node_safe(str, tmp, &mix_role_list) {
			switch (who_am_i(str->str)) {
			case ROLE_NONE:
			case ROLE_TESTER:
			case ROLE_MIX:
				return ROLE_NONE;
			default:
				break;
			}
		}
		return ROLE_MIX;
	}

	return ROLE_NONE;
}

static void print_help(void)
{
	printf(
	"\n"
	"Usage: ulpatch_test [OPTION]... \n"
	"\n"
	"  Exe: %s\n"
	"\n"
	"Test ulpatch\n"
	"\n",
	ulpatch_test_path
	);

	printf(
	"Tests:\n"
	"\n"
	" -l, --list-tests    list all tests\n"
	" -f, --filter [STR]  filter out some tests, (may be listed multiple times)\n"
	"\n");
	printf(
	"Role:\n"
	"\n"
	" -r, --role [ROLE]   who am i, what should i do\n"
	"                     '%s' test all Tests, see with -l, default.\n"
	"                     '%s' i will sleep %dus by default, set with -s.\n"
	"                     '%s' i will wait on msgrcv(2), specify by -m.\n"
	"                     '%s' i will msgsnd(2) a msg, specify by -m.\n"
	"                     '%s' i will loop print some message.\n"
	"                     '%s' i will startup a multi-thread printer process.\n"
	"                           number or threads set by --nr-threads, default: %d\n"
	"                     '%s' i will wait on msgrcv(2) with request, specify by -m.\n"
	"                     MIX:\n"
	"                       -r sleeper,sleeper, will launch sleeper twice\n"
	"\n",
	role_string[ROLE_TESTER],
	role_string[ROLE_SLEEPER],
	sleep_usec,
	role_string[ROLE_WAITING],
	role_string[ROLE_TRIGGER],
	role_string[ROLE_PRINTER],
	role_string[ROLE_MULTI_THREADS],
	nr_threads,
	role_string[ROLE_LISTENER]
	);
	printf(
	"   %s and %s arguments:\n"
	"     --print-nloop [NUM]   loop of print, default %d\n"
	"     --print-usec [N]      interval of print, default %d usec\n"
	"\n",
	role_string[ROLE_PRINTER],
	role_string[ROLE_MULTI_THREADS],
	print_nloop_default,
	print_interval_usec
	);
	printf(
	"   %s arguments:\n"
	"    Just execute once:\n"
	"     --listener-request  request from msgq, see --listener-req-list\n"
	"     --listener-req-list just show support request symbol\n"
	"     --listener-nloop    request from msgq for times, default %d\n"
	"\n"
	"    Execute for loop:\n"
	"     --listener-epoll    start a loop with epoll(2), see listener.c.\n"
	"                         if set, other --listener-??? argument skipped.\n"
	"\n",
	role_string[ROLE_LISTENER],
	listener_nloop
	);
	printf(
	"\n"
	" -s, --usecond [N]   usecond of time, sleep, etc.\n"
	"                     -r %s, the main thread will sleep -s useconds.\n"
	"\n"
	" -m, --msgq [STRING] key to ftok(3).\n"
	"                     -r %s, the main thread will wait on msgrcv(2).\n"
	"                     -r %s, the main thread will msgsnd(2) to msgq.\n"
	"                     -r %s, the main thread will msgrcv(2) a request on msgq.\n"
	"                            and send response.\n"
	"\n"
	"     --error-exit    Exit if error.\n"
	"\n",
	role_string[ROLE_SLEEPER],
	role_string[ROLE_WAITING],
	role_string[ROLE_TRIGGER],
	role_string[ROLE_LISTENER]
	);
	print_usage_common(prog_name);
}

enum {
	ARG_EXTRA_MIN = ARG_COMMON_MAX,
	ARG_PRINT_NLOOP,
	ARG_PRINT_INTERVAL_USEC,
	ARG_ERROR_EXIT,
	ARG_NR_THREADS,

	ARG_LISTENER_REQUEST,
	ARG_LISTENER_REQUEST_LIST,
	ARG_LISTENER_NLOOP,
	ARG_LISTENER_EPOLL,

	ARG_SKIP,
};

static int parse_config(int argc, char *argv[])
{
	struct option options[] = {
		{ "list-tests",         no_argument,        0,  'l' },
		{ "filter",             required_argument,  0,  'f' },
		{ "skip",               required_argument,  0,  ARG_SKIP },
		{ "role",               required_argument,  0,  'r' },
		{ "usecond",            required_argument,  0,  's' },
		{ "msgq",               required_argument,  0,  'm' },
		{ "print-nloop",        required_argument,  0,  ARG_PRINT_NLOOP },
		{ "nr-threads",         required_argument,  0,  ARG_NR_THREADS },
		{ "print-usec",         required_argument,  0,  ARG_PRINT_INTERVAL_USEC },
		{ "listener-request",   required_argument,  0,  ARG_LISTENER_REQUEST },
		{ "listener-req-list",  no_argument,        0,  ARG_LISTENER_REQUEST_LIST },
		{ "listener-nloop",     required_argument,  0,  ARG_LISTENER_NLOOP },
		{ "listener-epoll",     no_argument,        0,  ARG_LISTENER_EPOLL },
		{ "error-exit",         no_argument,        0,  ARG_ERROR_EXIT },
		COMMON_OPTIONS
		{ NULL }
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "lf:r:s:m:"COMMON_GETOPT_OPTSTRING,
				options, &option_index);
		if (c < 0) {
			break;
		}
		switch (c) {
		case 'l':
			just_list_tests = true;
			break;
		case 'f':
			add_filter_fmt(optarg, false);
			break;
		case ARG_SKIP:
			add_filter_fmt(optarg, true);
			break;
		case 'r':
			role = who_am_i(optarg);
			break;
		case 's':
			sleep_usec = atoi(optarg);
			break;
		case 'm':
			msgq_file = (char*)optarg;
			break;
		case ARG_PRINT_NLOOP:
			print_nloop_default = atoi(optarg);
			break;
		case ARG_NR_THREADS:
			nr_threads = atoi(optarg);
			break;
		case ARG_PRINT_INTERVAL_USEC:
			print_interval_usec = atoi(optarg);
			break;
		case ARG_LISTENER_REQUEST:
			listener_request = optarg;
			break;
		case ARG_LISTENER_REQUEST_LIST:
			listener_request_list = true;
			break;
		case ARG_LISTENER_NLOOP:
			listener_nloop = atoi(optarg);
			break;
		case ARG_LISTENER_EPOLL:
			listener_epoll = true;
			break;
		case ARG_ERROR_EXIT:
			error_exit = true;
			break;
		COMMON_GETOPT_CASES(prog_name, print_help, argv)
		default:
			print_help();
			exit(1);
			break;
		}
	}

	if (role == ROLE_NONE) {
		fprintf(stderr, "wrong -r, --role argument.\n");
		exit(1);
	}

	if (print_nloop_default <= 0) {
		fprintf(stderr, "wrong --print-nloop argument.\n");
		exit(1);
	}

	if (print_interval_usec <= 0) {
		fprintf(stderr, "wrong --print-usec argument.\n");
		exit(1);
	}

	if (sleep_usec <= 0 || sleep_usec > 999000000) {
		fprintf(stderr, "wrong -s, --usecond argument, 0 < X < 999000000\n");
		exit(1);
	}

	if (role == ROLE_LISTENER) {
		if (listener_request_list) {
			print_test_symbol();
			exit(0);
		}

		if (!listener_epoll && !listener_request) {
			fprintf(stderr, "%s need set --listener-request\n",
				role_string[ROLE_LISTENER]);
			exit(1);
		}
		if (!listener_epoll && !msgq_file) {
			fprintf(stderr, "Need a ftok(3) file input with -m.\n");
			exit(1);
		}
		if (!listener_epoll && listener_nloop < 1) {
			fprintf(stderr, "--listener-nloop need >= 1.\n");
			exit(1);
		}
	}

	if (msgq_file && !fexist(msgq_file)) {
		fprintf(stderr, "%s not exist.\n", msgq_file);
		exit(1);
	}

	return 0;
}

static int show_test(struct test *test, bool after_test)
{
	fprintf(stderr, " %4d/%-4d  %-4d %s.%s",
		test->idx, nr_tests, test->prio, test->category, test->name);

	if (after_test)
		fprintf(stderr, "\tret:%d:%d", test->expect_ret, test->real_ret);
	else
		fprintf(stderr, "\texpect_ret:%d", test->expect_ret);

	fprintf(stderr, "\n");
	return 0;
}

static bool should_skip(struct test *test)
{
	/* If specify nothing, test all tests by default */
	bool skip = false;
	char category_name[256];

	/* Default: test all */
	if (!has_filter())
		return false;

	snprintf(category_name, 256, "%s.%s", test->category, test->name);

	if (has_filter_match() && filter_matched(category_name))
		skip = false;
	else if (has_filter_match())
		skip = true;

	if (!skip && filter_matched_skip(category_name))
		skip = true;

	/**
	 * If priority is too high, it couldn't be skipped.
	 */
	if (skip && test->prio < TEST_PRIO_HIGHER)
		skip = false;

	return skip;
}

static int operate_test(struct test *test)
{
	bool failed = false;
	int verbose;

	errno = 0;

	if (!test->test_cb)
		return -EINVAL;

	test_log("=== %4d/%-4d %s.%s %c",
		test->idx, nr_tests,
		test->category, test->name,
		is_verbose() ? '\n' : '\0');

	current_test = test;

	gettimeofday(&test->start, NULL);

	/* Exe test entry */
	verbose = get_verbose();
	test->real_ret = test->test_cb();
	enable_verbose(verbose);
	if (test->real_ret == test->expect_ret || test->expect_ret == TEST_RET_SKIP) {
		stat_count[STAT_IDX_SUCCESS]++;
	} else {
		stat_count[STAT_IDX_FAILED]++;
		failed = true;
		list_add(&test->failed, &failed_list);
	}

	gettimeofday(&test->end, NULL);

	test->spend_us = test->end.tv_sec * 1000000UL + test->end.tv_usec
		- test->start.tv_sec * 1000000UL - test->start.tv_usec;

	total_spent_us += test->spend_us;

	current_test = NULL;

	test_log("\033[2m%ldus\033[m %s%-8s%s %s ret:%d:%d\n",
		test->spend_us,
		failed ? "\033[31m" : "\033[32m",
		failed ? "Failed: " : "OK",
		failed ? (
				str_special_ret(test->real_ret) ?: strerror(errno)
			) : "",
		"\033[m",
		test->expect_ret, test->real_ret);

	if (failed) {
		/**
		 * 1. high priority failed
		 * 2. ordinary test failed, and set --error-exit argument
		 */
		if (test->prio < TEST_PRIO_MIDDLE || error_exit)
			return -1;
	}

	return 0;
}

static void launch_tester(void)
{
	int i, fd;
	struct test *test = NULL;

	test_log("=========================================\n");
	test_log("===\n");
	test_log("=== ULPatch Testing\n");
	test_log("===\n");
	test_log("===  version: %s\n", ulpatch_version());
	test_log("=== ---------------------------\n");

	if (just_list_tests) {
		fprintf(stderr,
			"\n"
			"Show test list\n"
			"\n"
			" %-10s %-4s %s.%s\n",
			"Idx/NUM", "Prio", "Category", "name"
		);
	}

	if (!is_verbose() && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	}

	/* for each priority */
	for (i = 0; i < TEST_PRIO_NUM; i++) {
		/* for each test entry */
		list_for_each_entry(test, &test_list[i], node) {
			int ret;
			if (should_skip(test))
				continue;

			if (just_list_tests) {
				show_test(test, false);
				continue;
			}

			ret = operate_test(test);
			/* if error */
			if (ret != 0)
				goto print_stat;
		}
	}

print_stat:

	if (just_list_tests) {
		fprintf(stderr, "\n");
		return;
	}

	unsigned long total = stat_count[STAT_IDX_SUCCESS]
				+ stat_count[STAT_IDX_FAILED];
	fprintf(stderr,
		"=========================================\n"
		"=== Total %ld tested\n"
		"===  Success %ld\n"
		"===  Failed %ld\n"
		"===  Spend %ldms %.2lfms/per\n",
		total,
		stat_count[STAT_IDX_SUCCESS],
		stat_count[STAT_IDX_FAILED],
		total_spent_us / 1000,
		total_spent_us * 1.0f / total / 1000.0f
	);

	if (stat_count[STAT_IDX_FAILED] > 0) {
		fprintf(stderr,
			"\n"
			"Show failed test list\n"
			"\n"
			" %-10s  %-4s %s.%s\n",
			"Idx/NUM", "Prio", "Category", "name"
		);
		list_for_each_entry(test, &failed_list, failed)
			show_test(test, true);
	}
	test_log("=========================================\n");
}

static void launch_printer(void);

static void *thread1(void *arg)
{
	launch_printer();
	return NULL;
}

static void launch_multi_thread(void)
{
	int i;
	pthread_t *threads;

	if (nr_threads <= 0) {
		fprintf(stderr, "OMG! number of thread is %d <= 0.\n", nr_threads);
		return;
	}

	threads = malloc(sizeof(pthread_t) * nr_threads);

	for (i = 0; i < nr_threads; i++)
		pthread_create(&threads[i], NULL, thread1, NULL);

	for (i = 0; i < nr_threads; i++)
		pthread_join(threads[i], NULL);

	free(threads);
	return;
}

static void launch_sleeper(void)
{
	usleep(sleep_usec);
}

static void launch_waiting(void)
{
	struct task_notify wait_here;

	if (!msgq_file) {
		fprintf(stderr, "Need a ftok(3) file input with -m.\n");
		exit(1);
	}

	task_notify_init(&wait_here, msgq_file);
	ulp_debug("CHILD: wait msg.\n");
	task_notify_wait(&wait_here);
	ulp_debug("CHILD: return.\n");
	// task_notify_destroy(&wait_here);
}

static void launch_trigger(void)
{
	struct task_notify wait_here;

	if (!msgq_file) {
		fprintf(stderr, "Need a ftok(3) file input with -m.\n");
		exit(1);
	}

	task_notify_init(&wait_here, msgq_file);
	ulp_debug("CHILD: send msg.\n");
	task_notify_trigger(&wait_here);
	ulp_debug("CHILD: return.\n");
	// task_notify_destroy(&wait_here);
}

static void static_func1(void)
{
}

int printer_print_hello(int nloop, const char *content)
{
	int ret = 0;
	ret += printf("%d %s %s:%p, %s:%p, %s:%p\n", nloop, print_content,
			__stringify(puts), puts,
			__stringify(printer_print_hello), printer_print_hello,
			__stringify(static_func1), static_func1);
	hello_world();
	return 0;
}

static void launch_printer(void)
{
	int nloop = print_nloop_default;

	while (nloop--) {
		printer_print_hello(nloop, print_content);
		usleep(print_interval_usec);
	}
}

static void launch_listener(void);

static void launch_mix_role(enum who r)
{
	switch (r) {
	case ROLE_SLEEPER:
		launch_sleeper();
		break;
	case ROLE_WAITING:
		launch_waiting();
		break;
	case ROLE_TRIGGER:
		launch_trigger();
		break;
	case ROLE_PRINTER:
		launch_printer();
		break;
	case ROLE_LISTENER:
		launch_listener();
		break;
	case ROLE_MIX:
	case ROLE_TESTER:
		fprintf(stderr, "Not support %s in mix role.\n", role_string[r]);
		exit(1);
	default:
		print_help();
		exit(1);
		break;
	}
}

static void launch_mix(void)
{
	ulp_debug("MIX\n");
	struct str_node *str = NULL, *tmp;

	strstr_for_each_node_safe(str, tmp, &mix_role_list) {
		ulp_debug("MIX: %s\n", str->str);
		launch_mix_role(who_am_i(str->str));
	}
}


struct test_symbol test_symbols[] = {
#define TEST_FUNC_SYM(s) { __stringify(s), 0, TYPE_TST_SYM_FUNC, },
#define TEST_DATA_SYM(s) { __stringify(s), 0, TYPE_TST_SYM_DATA, },
# include <tests/test-symbols.h>
#undef TEST_FUNC_SYM
#undef TEST_DATA_SYM
};

size_t nr_test_symbols(void)
{
	return ARRAY_SIZE(test_symbols);
}

/**
 * We need to assign a value to the symbol address after the process starts,
 * because static assignment is not allowed.
 */
static void init_test_symbols(void)
{
	int i;
#define TEST_SYM_FOR_EACH
#define TEST_SYM_FOR_EACH_I i
#define TEST_SYM_ARRAY_NAME test_symbols
#define TEST_FUNC_SYM(s) \
	if (!strcmp(#s, test_symbols[i].sym) && test_symbols[i].type == TYPE_TST_SYM_FUNC) {	\
		test_symbols[i].addr = (unsigned long)s;	\
		ulp_debug("Sym %s addr %lx\n", #s, test_symbols[i].addr);	\
	}
/* DATA need '&' operater */
#define TEST_DATA_SYM(s) \
	if (!strcmp(#s, test_symbols[i].sym) && test_symbols[i].type == TYPE_TST_SYM_DATA) {	\
		test_symbols[i].addr = (unsigned long)&s;	\
		ulp_debug("Sym %s addr %lx\n", #s, test_symbols[i].addr);	\
	}
# include <tests/test-symbols.h>
#undef TEST_FUNC_SYM
#undef TEST_DATA_SYM
#undef TEST_SYM_FOR_EACH_I
#undef TEST_SYM_ARRAY_NAME
#undef TEST_SYM_FOR_EACH
}

struct test_symbol *find_test_symbol(const char *sym)
{
	int i;
	struct test_symbol *s = NULL;

	for (i = 0; i < nr_test_symbols(); i++)
		if (!strcmp(test_symbols[i].sym, sym))
			s = &test_symbols[i];

	return s;
}

static void print_test_symbol(void)
{
	int i;
	struct test_symbol *s = NULL;

	for (i = 0; i < nr_test_symbols(); i++) {
		s = &test_symbols[i];
		fprintf(stdout, "%3d \t %-s\n", i + 1, s->sym);
	}
}

#define REQUEST_SYM_ADDR	1

static int response_msg(struct msgbuf *buf, size_t buf_len)
{
	int ret = 0;

	struct test_symbol *sym = find_test_symbol(listener_request);

	if (!sym) {
		fprintf(stderr, "%s no exist in tests.\n", listener_request);
		return sizeof(char);
	}

	*(unsigned long *)&buf->mtext[1] = sym->addr;

	/* address + mtext[0] */
	ret = sizeof(unsigned long) + sizeof(char);

	return ret;
}

static int listener_rspmsg(char request, struct msgbuf *buf, size_t buf_len)
{
	switch (request) {
	case REQUEST_SYM_ADDR:
		return response_msg(buf, buf_len);
	default:
		break;
	}
	return sizeof(char);
}

static void launch_listener_once(void)
{
	struct task_notify notify;

	ulp_debug("LAUNCH: %s %s\n", role_string[ROLE_LISTENER], listener_request);

	task_notify_init(&notify, msgq_file);

	while (listener_nloop--) {
		task_notify_response(&notify, listener_rspmsg);
	}

	// task_notify_destroy(&notify);
}

static void launch_listener(void)
{
	if (listener_epoll) {
		init_listener();
		listener_main_loop(NULL);
	} else {
		launch_listener_once();
	}
}

static void sig_handler(int signum)
{
	switch (signum) {
	case SIGINT:
		fprintf(stderr, "Catch Ctrl-C, bye\n");
		if (listener_epoll)
			close_listener();
		free_strstr_list(&mix_role_list);
		release_tests();
		/* exit abnormal */
		exit(1);
		break;
	case SIGILL:
	case SIGSEGV:
		ulp_emerg("Catch emerge signal.\n");
		do_backtrace(stdout);
		GO_BACK_TO_TEST_AND_SKIP_TEST();
		exit(1);
		break;
	}
}

void never_called_stub(void)
{
	CALL_TEST_STUB(arch_ftrace);
	CALL_TEST_STUB(arch_instruments);
	CALL_TEST_STUB(arch_mcount);
	CALL_TEST_STUB(cmds_common);
	CALL_TEST_STUB(cmds_ulftrace);
	CALL_TEST_STUB(cmds_ulpatch);
	CALL_TEST_STUB(cmds_ulpinfo);
	CALL_TEST_STUB(cmds_ultask);
	CALL_TEST_STUB(elf_core);
	CALL_TEST_STUB(elf_ehdr);
	CALL_TEST_STUB(elf_open);
	CALL_TEST_STUB(elf_relocs);
	CALL_TEST_STUB(elf_symbol);
	CALL_TEST_STUB(elf_symbol_bfd);
	CALL_TEST_STUB(ftrace_ftrace);
	CALL_TEST_STUB(patch_asm);
	CALL_TEST_STUB(patch_meta);
	CALL_TEST_STUB(patch_object);
	CALL_TEST_STUB(patch_patch);
	CALL_TEST_STUB(patch_symbol);
	CALL_TEST_STUB(task_core);
	CALL_TEST_STUB(task_current);
	CALL_TEST_STUB(task_proc);
	CALL_TEST_STUB(task_symbol);
	CALL_TEST_STUB(task_vma);
	CALL_TEST_STUB(utils_ansi);
	CALL_TEST_STUB(utils_backtrace);
	CALL_TEST_STUB(utils_disasm);
	CALL_TEST_STUB(utils_file);
	CALL_TEST_STUB(utils_id);
	CALL_TEST_STUB(utils_init);
	CALL_TEST_STUB(utils_list);
	CALL_TEST_STUB(utils_log);
	CALL_TEST_STUB(utils_rbtree);
	CALL_TEST_STUB(utils_string);
	CALL_TEST_STUB(utils_utils);
	CALL_TEST_STUB(utils_version);
}

static void ulpatch_test_args_reset_stub(void)
{
}

int main(int argc, char *argv[])
{
	COMMON_RESET_BEFORE_PARSE_ARGS(ulpatch_test_args_reset_stub);

	static char ulpatch_test_path_buf[PATH_MAX];

	ulpatch_test_path = get_proc_pid_exe(getpid(), ulpatch_test_path_buf,
					     PATH_MAX);
	if (!ulpatch_test_path || !fexist(ulpatch_test_path)) {
		ulp_error("Not found ulpatch_test path.\n");
		return -ENOENT;
	}

	ulpatch_init();

	signal(SIGINT, sig_handler);
	signal(SIGSEGV, sig_handler);
	signal(SIGILL, sig_handler);

	parse_config(argc, argv);

	COMMON_IN_MAIN_AFTER_PARSE_ARGS();

	init_test_symbols();

	switch (role) {
	case ROLE_TESTER:
		launch_tester();
		break;
	case ROLE_MULTI_THREADS:
		launch_multi_thread();
		break;
	case ROLE_SLEEPER:
	case ROLE_WAITING:
	case ROLE_TRIGGER:
	case ROLE_PRINTER:
	case ROLE_LISTENER:
		launch_mix_role(role);
		break;
	case ROLE_MIX:
		launch_mix();
		break;
	default:
		print_help();
		exit(1);
		break;
	}

	free_strstr_list(&mix_role_list);
	release_tests();
	free_filter_fmt_list();

	return 0;
}

/* There are some selftests */

TEST(ulpatch_test, sleeper, 0)
{
	int ret = 0;
	int status = 0;

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			(char*)ulpatch_test_path,
			"-r", "sleeper",
			"-s", "100",
			NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	}

	/* Parent */
	waitpid(pid, &status, __WALL);
	if (status != 0)
		ret = -EINVAL;
	return ret;
}

TEST(ulpatch_test, wait, 0)
{
	int ret = 0;
	int status = 0;
	pid_t pid;

	struct task_notify notify;

	task_notify_init(&notify, NULL);

	pid = fork();
	if (pid == 0) {
		int ret;

		char *_argv[] = {
			(char*)ulpatch_test_path,
			"--role", "wait",
			"--msgq", notify.tmpfile,
			NULL,
		};
		ulp_debug("PARENT: fork one.\n");
		ret = execvp(_argv[0], _argv);
		if (ret == -1) {
			exit(1);
		}
	}

	/* do something */
	ulp_debug("PARENT: msgsnd to child.\n");
	task_notify_trigger(&notify);
	ulp_debug("PARENT: send done.\n");
	waitpid(pid, &status, __WALL);
	if (status != 0)
		ret = -EINVAL;

	task_notify_destroy(&notify);

	return ret;
}

TEST(ulpatch_test, trigger, 0)
{
	int ret = 0;
	int status = 0;
	pid_t pid;

	struct task_notify notify;

	task_notify_init(&notify, NULL);

	pid = fork();
	if (pid == 0) {
		int ret;

		char *_argv[] = {
			(char*)ulpatch_test_path,
			"--role", "trigger",
			"--msgq", notify.tmpfile,
			NULL,
		};
		ulp_debug("PARENT: fork one.\n");
		ret = execvp(_argv[0], _argv);
		if (ret == -1) {
			exit(1);
		}

	}

	/* do something */
	ulp_debug("PARENT: waiting.\n");
	task_notify_wait(&notify);
	ulp_debug("PARENT: get msg.\n");
	waitpid(pid, &status, __WALL);
	if (status != 0)
		ret = -EINVAL;

	task_notify_destroy(&notify);

	return ret;
}

TEST(ulpatch_test, wait_wait_wait, 0)
{
	int ret = 0;
	int status = 0;
	pid_t pid;

	struct task_notify notify;

	task_notify_init(&notify, NULL);

	pid = fork();
	if (pid == 0) {
		int ret;

		char *_argv[] = {
			(char*)ulpatch_test_path,
			"--role", "wait,sleeper,wait,sleeper,wait",
			"--msgq", notify.tmpfile,
			NULL,
		};
		ulp_debug("PARENT: fork one.\n");
		ret = execvp(_argv[0], _argv);
		if (ret == -1) {
			exit(1);
		}

	}

	/* do something */
	ulp_debug("PARENT: msgsnd to child.\n");
	task_notify_trigger(&notify);
	task_notify_trigger(&notify);
	task_notify_trigger(&notify);
	ulp_debug("PARENT: done.\n");
	waitpid(pid, &status, __WALL);
	if (status != 0)
		ret = -EINVAL;

	task_notify_destroy(&notify);

	return ret;
}

TEST(ulpatch_test, trigger_trigger_trigger, 0)
{
	int ret = 0;
	int status = 0;
	pid_t pid;

	struct task_notify notify;

	task_notify_init(&notify, NULL);

	pid = fork();
	if (pid == 0) {
		int ret;

		char *_argv[] = {
			(char*)ulpatch_test_path,
			"--role", "trigger,sleeper,trigger,sleeper,trigger",
			"--msgq", notify.tmpfile,
			NULL,
		};
		ulp_debug("PARENT: fork one.\n");
		ret = execvp(_argv[0], _argv);
		if (ret == -1) {
			exit(1);
		}

	}

	/* do something */
	ulp_debug("PARENT: wait child.\n");
	task_notify_wait(&notify);
	task_notify_wait(&notify);
	task_notify_wait(&notify);

	ulp_debug("PARENT: get msgs from child.\n");
	waitpid(pid, &status, __WALL);
	if (status != 0)
		ret = -EINVAL;

	task_notify_destroy(&notify);

	return ret;
}

TEST(ulpatch_test, wait_trigger, 0)
{
	int ret = 0;
	int status = 0;
	pid_t pid;

	struct task_notify notify;

	task_notify_init(&notify, NULL);

	pid = fork();
	if (pid == 0) {
		int ret;

		char *_argv[] = {
			(char*)ulpatch_test_path,
			"--role", "wait,trigger,wait,trigger",
			"--msgq", notify.tmpfile,
			NULL,
		};
		ulp_debug("PARENT: fork one.\n");
		ret = execvp(_argv[0], _argv);
		if (ret == -1) {
			exit(1);
		}

	}

	/* do something */
	ulp_debug("PARENT: do some thing.\n");
	task_notify_trigger(&notify);
	task_notify_wait(&notify);
	task_notify_trigger(&notify);
	task_notify_wait(&notify);

	ulp_debug("PARENT: done.\n");
	waitpid(pid, &status, __WALL);
	if (status != 0)
		ret = -EINVAL;

	task_notify_destroy(&notify);

	return ret;
}

static int test_listener_symbol(char request, char *sym)
{
	int ret = 0;
	int status = 0;
	pid_t pid;

	struct task_notify notify;

	task_notify_init(&notify, NULL);

	pid = fork();
	if (pid == 0) {
		int ret;
		char lv[16];
		sprintf(lv, "%d", get_log_level());
		char *_argv[] = {
			(char*)ulpatch_test_path,
			"--role", "listener",
			"--msgq", notify.tmpfile,
			"--listener-request", sym,
			"--log-level", lv,
			NULL,
		};
		ret = execvp(_argv[0], _argv);
		if (ret == -1) {
			exit(1);
		}

	}

	char buffer[BUFFER_SIZE];
	struct msgbuf *rx_buf = (void *)buffer;

	task_notify_request(&notify, REQUEST_SYM_ADDR, rx_buf, BUFFER_SIZE);

	unsigned long addr = *(unsigned long *)&rx_buf->mtext[1];

	ulp_info("%s: addr 0x%lx\n", sym, addr);

	waitpid(pid, &status, __WALL);
	if (status != 0)
		ret = -EINVAL;

	task_notify_destroy(&notify);

	return ret;
}

TEST(ulpatch_test, listener, 0)
{
	int i;
	for (i = 0; i < nr_test_symbols(); i++)
		test_listener_symbol(REQUEST_SYM_ADDR, test_symbols[i].sym);
	return 0;
}

TEST(ulpatch_test, listener_epoll, 0)
{
	int ret = 0;
	int status = 0;
	pid_t pid;
	int fd = -1, i, rslt;

	struct task_notify notify;

	task_notify_init(&notify, NULL);

	pid = fork();
	if (pid == 0) {
		int ret;

		char *_argv[] = {
			(char*)ulpatch_test_path,
			"--role", "listener",
			"--listener-epoll",
			NULL,
		};
		ret = execvp(_argv[0], _argv);
		if (ret == -1) {
			exit(1);
		}

	}

	/**
	 * Wait for server init done. this method is not perfect.
	 */
	usleep(10000);

	fd = listener_helper_create_test_client();

	if (fd <= 0)
		ret = -1;

	for (i = 0; i < nr_test_symbols(); i++) {
		unsigned long addr;

		listener_helper_symbol(fd, test_symbols[i].sym, &addr);

		ulp_info("%-10s: %lx\n", test_symbols[i].sym, addr);
	}

	listener_helper_close(fd, &rslt);
	listener_helper_close_test_client(fd);

	waitpid(pid, &status, __WALL);
	if (status != 0)
		ret = -EINVAL;

	task_notify_destroy(&notify);

	return ret;
}

