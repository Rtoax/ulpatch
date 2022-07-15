#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>
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

#define test_log(fmt...) \
	fprintf(stderr, fmt);

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

// For -V, --verbose
static bool verbose = false;

static void print_help(void)
{
	printf(
	"\n"
	"Usage: elftools_test [OPTION]... \n"
	"\n"
	"Test elftools\n"
	"\n"
	"Mandatory arguments to long options are mandatory for short options too.\n"
	"\n"
	" -l, --list-tests    list all tests\n"
	" -f, --filter-tests  filter out some tests\n"
	" -V, --verbose       output all test logs\n"
	" -h, --help          display this help and exit\n"
	" -v, --version       output version information and exit\n"
	"\n"
	"elftools_test %s\n",
	elftools_version()
	);
	exit(0);
}

static int parse_config(int argc, char *argv[])
{
	struct option options[] = {
		{"list-tests",	no_argument,	0,	'l'},
		{"filter-tests",	required_argument,	0,	'f'},
		{"verbose",	no_argument,	0,	'V'},
		{"version",	no_argument,	0,	'v'},
		{"help",	no_argument,	0,	'h'},
		{NULL}
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "lf:Vvh", options, &option_index);
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
		case 'V':
			verbose = true;
			break;
		case 'v':
			printf("version %s\n", elftools_version());
			exit(0);
		case 'h':
			print_help();
		default:
			print_help();
			break;
		}
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

	// Exe test entry
	ret = test->test_cb();
	if (ret == test->expect_ret) {
		stat_count[0]++;
	} else {
		stat_count[1]++;

		failed = true;

		list_add(&test->failed, &failed_list);
	}
	
	test_log("=== %s%-8s%s %s.%s\n",
		failed?"\033[31m":"\033[32m",
		failed?"Not OK":"OK",
		"\033[m",
		test->category, test->name);

	if (failed && test->prio < TEST_PRIO_MIDDLE) {
		/**
		 * Only high priority test return -1
		 */
		return -1;
	}

	return 0;
}

/**
 * __main__
 */
int main(int argc, char *argv[])
{
	int i, fd;
	struct test *test = NULL;

	parse_config(argc, argv);

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
	}

	return 0;
}
