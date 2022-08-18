// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/time.h>
#include <sys/msg.h>

#include <utils/list.h>
#include <utils/compiler.h>

#if defined(__x86_64__)
#include <arch/x86_64/regs.h>
#include <arch/x86_64/instruments.h>
#include <arch/x86_64/ftrace.h>
#elif defined(__aarch64__)
#include <arch/aarch64/regs.h>
#include <arch/aarch64/instruments.h>
#include <arch/aarch64/ftrace.h>
#endif

/**
 * test prio
 *
 */
typedef enum {
// constructor priorities from 0 to 100 are reserved for the implementation
#define TEST_PRIO_START	CTOR_PRIO_USER
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


#ifdef PRINTER_FN
# error "Redefine PRINTER_FN"
#endif
#define PRINTER_FN	print_hello
int PRINTER_FN(int nloop, const char *content);


#define LIBC_PUTS_FN	puts


struct test*
create_test(char *category, char *name, test_prio prio, int (*cb)(void),
	int expect_ret);
void release_tests(void);

/* Add wait api */
struct task_wait {
	int msqid;
	char tmpfile[64];
};

extern void mcount(void);
extern void _mcount(void);

int task_wait_init(struct task_wait *task_wait, char *tmpfile);
int task_wait_destroy(struct task_wait *task_wait);
int task_wait_wait(struct task_wait *task_wait);
int task_wait_trigger(struct task_wait *task_wait);
int task_wait_request(struct task_wait *task_wait, char request,
	struct msgbuf *rx_buf, size_t rx_buf_size);
int task_wait_response(struct task_wait *task_wait,
	int (*makemsg)(char request, struct msgbuf *buf, size_t buf_len));

