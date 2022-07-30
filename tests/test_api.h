#include <stdlib.h>
#include <malloc.h>
#include <sys/time.h>

#include <utils/list.h>
#include <utils/compiler.h>

/**
 * test prio
 *
 */
typedef enum {
// constructor priorities from 0 to 100 are reserved for the implementation
#define TEST_PRIO_START	101
	TEST_HIGHEST = 1,
#define TEST_PRIO_HIGHEST	TEST_PRIO_START + TEST_HIGHEST
	TEST_HIGHER,
#define TEST_PRIO_HIGHER	TEST_PRIO_START + TEST_HIGHER
	TEST_MIDDLE,
#define TEST_PRIO_MIDDLE	TEST_PRIO_START + TEST_MIDDLE
	TEST_LOWER,
#define TEST_PRIO_LOWER	TEST_PRIO_START + TEST_LOWER
	TEST_PRIO_NUM
} test_prio;

/**
 * test entry
 *
 */
struct test {
	char *category;
	char *name;
	test_prio prio;
	int (*test_cb)(void);
	int expect_ret;

	// record testing time spend
	struct timeval start, end;
	suseconds_t spend_us;

	struct list_head node;
	// if test result is failed, add to 'failed_list'
	struct list_head failed;
};

/**
 * Define a test
 *
 */
#define __TEST(Category, Name, Prio, Ret) \
	int test_ ##Category ##_##Name(void);	\
	static void __ctor(Prio) test_ctor_ ##Category ##_##Name(void) {	\
		struct test __unused *test = \
			create_test(#Category, #Name, \
				Prio, test_ ##Category ##_##Name, Ret);	\
	}	\
	int test_ ##Category ##_##Name(void)

// Highest prio TEST
#define TEST_HIGHEST(Category, Name, Ret)	\
	__TEST(Category, Name, TEST_PRIO_HIGHEST, Ret)

// Normal prio TEST
#define TEST(Category, Name, Ret)	\
	__TEST(Category, Name, TEST_PRIO_MIDDLE, Ret)

// Lower prio TEST
#define TEST_LOWER(Category, Name, Ret)	\
	__TEST(Category, Name, TEST_PRIO_LOWER, Ret)

extern struct list_head test_list[TEST_PRIO_NUM];

extern const char *elftools_test_path;

struct test*
create_test(char *category, char *name, test_prio prio, int (*cb)(void),
	int expect_ret);
void release_tests(void);

