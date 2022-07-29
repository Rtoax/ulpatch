#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>
#include <utils/task.h>
#include <elf/elf_api.h>

#include "test_api.h"

#ifdef HAVE_CUNIT
#else
#endif

struct list_head test_list[TEST_PRIO_NUM];
static LIST_HEAD(failed_list);

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

#define test_ok(fmt...) \
	fprintf(stderr, "\033[32m");	\
	fprintf(stderr, fmt);	\
	fprintf(stderr, "\033[m");

#define test_failed(fmt...) \
	fprintf(stderr, "\033[31m");	\
	fprintf(stderr, fmt);	\
	fprintf(stderr, "\033[m");


// 0-success, 1-failed
static unsigned long stat_count[2] = {0};

// For -l, --list-tests
static bool just_list_tests = false;
// For -f, --filter-tests
static char *filter_format = NULL;

// For -r, --role
static enum who {
	ROLE_NONE,
	ROLE_TESTER, // testing all Tests
	ROLE_SLEEPER, // be tested
	ROLE_WAITING, // wait for a while
	ROLE_MAX,
} role = ROLE_TESTER;

static const char *role_string[ROLE_MAX] = {
	[ROLE_NONE] = "none",
	[ROLE_TESTER] = "tester",
	[ROLE_SLEEPER] = "sleeper",
	[ROLE_WAITING] = "wait",
};

static int sleep_usec = 100;
static char *wait_msg_file = NULL;

static char elftools_test_path_buf[MAX_PATH];
const char *elftools_test_path = NULL;

// For -V, --verbose
static bool verbose = false;

static enum who who_am_i(const char *s)
{
	int i;

	for (i = ROLE_TESTER; i < ARRAY_SIZE(role_string); i++) {
		if (!strcmp(s, role_string[i])) {
			return i;
		}
	}

	return 0;
}

static void print_help(int ex)
{
	printf(
	"\n"
	"Usage: elftools_test [OPTION]... \n"
	"\n"
	"  Exe: %s\n"
	"\n"
	"Test elftools\n"
	"\n"
	"Mandatory arguments to long options are mandatory for short options too.\n"
	"\n"
	" -l, --list-tests    list all tests\n"
	" -f, --filter-tests  filter out some tests\n"
	" -r, --role          who am i, what should i do\n"
	"                     '%s' test all Tests, see with -l, default.\n"
	"                     '%s' i will sleep %ds by default, set with -s.\n"
	"                     '%s' i will wait on msgrcv(2), specify by -m.\n"
	"\n"
	" -s, --usecond       usecond of time, sleep, etc.\n"
	"                     -r %s, the main thread will sleep -s useconds.\n"
	" -m, --msgq          wait one msgrcv(2)'s file, this arg wait a msg.\n"
	"                     -r %s, the main thread will wait on msgrcv(2).\n"
	"\n"
	" -V, --verbose       output all test logs\n"
	" -h, --help          display this help and exit\n"
	" -v, --version       output version information and exit\n"
	"\n"
	"elftools_test %s\n",
	elftools_test_path,
	role_string[ROLE_TESTER],
	role_string[ROLE_SLEEPER],
	sleep_usec,
	role_string[ROLE_WAITING],
	role_string[ROLE_SLEEPER],
	role_string[ROLE_WAITING],
	elftools_version()
	);
	exit(ex);
}

static int parse_config(int argc, char *argv[])
{
	struct option options[] = {
		{"list-tests",	no_argument,	0,	'l'},
		{"filter-tests",	required_argument,	0,	'f'},
		{"role",	required_argument,	0,	'r'},
		{"usecond",	required_argument,	0,	's'},
		{"msgq",	required_argument,	0,	'm'},
		{"verbose",	no_argument,	0,	'V'},
		{"version",	no_argument,	0,	'v'},
		{"help",	no_argument,	0,	'h'},
		{NULL}
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "lf:r:s:m:Vvh", options, &option_index);
		if (c < 0) {
			break;
		}
		switch (c) {
		case 'l':
			just_list_tests = true;
			break;
		case 'f':
			filter_format = optarg;
			break;
		case 'r':
			role = who_am_i(optarg);
			break;
		case 's':
			sleep_usec = atoi(optarg);
			break;
		case 'm':
			wait_msg_file = (char*)optarg;
			break;
		case 'V':
			verbose = true;
			break;
		case 'v':
			printf("version %s\n", elftools_version());
			exit(0);
		case 'h':
			print_help(0);
			break;
		default:
			print_help(1);
			break;
		}
	}

	if (role == ROLE_NONE) {
		fprintf(stderr, "wrong -r, --role argument.\n");
		exit(1);
	}

	if (sleep_usec <= 0 || sleep_usec > 999000000) {
		fprintf(stderr, "wrong -s, --second argument, 0 < X < 999\n");
		exit(1);
	}

	return 0;
}

static int show_test(struct test *test)
{
	fprintf(stderr, "  %-4d %s.%s\n", test->prio, test->category, test->name);
	return 0;
}

static bool filter_out_test(struct test *test)
{
	if (filter_format) {
		char category_name[256];
		snprintf(category_name, 256, "%s.%s",
			test->category, test->name);

		if (strstr(category_name, filter_format)) {
			return false;
		} else if (test->prio < TEST_PRIO_HIGHER) {
			if (just_list_tests) return true;
			else return false;
		} else {
			return true;
		}
	}

	// Default: test all
	return false;
}

static int operate_test(struct test *test)
{
	int ret;
	bool failed = false;

	if (!test->test_cb) return -1;

	test_log("=== %s.%s ",
		test->category, test->name);

	// Exe test entry
	ret = test->test_cb();
	if (ret == test->expect_ret) {
		stat_count[0]++;
	} else {
		stat_count[1]++;

		failed = true;

		list_add(&test->failed, &failed_list);
	}

	test_log("%s%-8s%s\n",
		failed?"\033[31m":"\033[32m",
		failed?"Not OK":"OK",
		"\033[m");

	if (failed && test->prio < TEST_PRIO_MIDDLE) {
		/**
		 * Only high priority test return -1
		 */
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
	test_log("=== ELFTools Testing\n");
	test_log("===\n");
	test_log("===  version: %s\n", elftools_version());
	test_log("=== ---------------------------\n");
	if (just_list_tests) {
		fprintf(stderr,
			"\n"
			"Show test list\n"
			"\n"
			"  %-4s %s.%s\n",
			"Prio", "Category", "name"
		);
	}

	if (!verbose && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	}

	// for each priority
	for (i = 0; i < TEST_PRIO_NUM; i++) {
		// for each test entry
		list_for_each_entry(test, &test_list[i], node) {
			int ret;

			if (just_list_tests) {
				if (filter_out_test(test)) continue;
				ret = show_test(test);
			} else {
				if (filter_out_test(test)) continue;
				ret = operate_test(test);
			}
			if (ret != 0) {
				goto print_stat;
			}
		}
	}

print_stat:

	if (just_list_tests) {
		fprintf(stderr, "\n");
	} else {
		fprintf(stderr,
			"=========================================\n"
			"=== Total %ld tested\n"
			"===  Success %ld\n"
			"===  Failed %ld\n",
			stat_count[0] + stat_count[1],
			stat_count[0],
			stat_count[1]
		);

		if (stat_count[1] > 0) {
			fprintf(stderr,
				"\n"
				"Show failed test list\n"
				"\n"
				"  %-4s %s.%s\n",
				"Prio", "Category", "name"
			);
			list_for_each_entry(test, &failed_list, failed) {
				show_test(test);
			}
		}
		test_log("=========================================\n");
	}

}

static void launch_sleeper(void)
{
	usleep(sleep_usec);
}

static void launch_waiting(void)
{
	struct task_wait wait_here;

	if (!wait_msg_file) {
		fprintf(stderr, "Need a ftok(2) file input with -m.\n");
		exit(1);
	}

	task_wait_init(&wait_here, wait_msg_file);
	ldebug("CHILD: wait msg.\n");
	task_wait_wait(&wait_here);
	ldebug("CHILD: return.\n");
	// task_wait_destroy(&wait_here);
}

static void sig_handler(int signum)
{
	switch (signum) {
	case SIGINT:
		fprintf(stderr, "Catch Ctrl-C, bye\n");
		release_tests();
		// exit abnormal
		exit(1);
		break;
	}
}

/**
 * __main__
 */
int main(int argc, char *argv[])
{
	signal(SIGINT, sig_handler);

	elftools_test_path =
		get_proc_pid_exe(getpid(), elftools_test_path_buf, MAX_PATH);

	parse_config(argc, argv);

	switch (role) {
	case ROLE_TESTER:
		launch_tester();
		break;
	case ROLE_SLEEPER:
		launch_sleeper();
		break;
	case ROLE_WAITING:
		launch_waiting();
		break;
	default:
		print_help(1);
		break;
	}

	release_tests();

	return 0;
}

/* There are some selftests */

TEST(elftools_test,	sleeper,	0)
{
	int ret = 0;
	int status = 0;

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			(char*)elftools_test_path,
			"-r", "sleeper",
			"-s", "100",
			NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	} else if (pid > 0) {
		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
	} else {
		lerror("fork(2) error.\n");
	}

	return ret;
}

TEST(elftools_test,	wait,	0)
{
	int ret = 0;
	int status = 0;
	pid_t pid;

	struct task_wait waitqueue;

	task_wait_init(&waitqueue, NULL);

	pid = fork();
	if (pid == 0) {
		int ret;

		char *_argv[] = {
			(char*)elftools_test_path,
			"--role", "wait",
			"--msgq", waitqueue.tmpfile,
			NULL,
		};
		ldebug("PARENT: fork one.\n");
		ret = execvp(_argv[0], _argv);
		if (ret == -1) {
			exit(1);
		}

	} else if (pid > 0) {

		// do something
		ldebug("PARENT: do 2s thing.\n");
		task_wait_trigger(&waitqueue, 10000);
		ldebug("PARENT: kick child.\n");
		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
	}

	task_wait_destroy(&waitqueue);

	return ret;
}

