// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
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
	TEST_PRIO_MIN,
/* constructor priorities from 0 to 100 are reserved for the implementation */
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
	int idx;
	char *category;
	char *name;
	test_prio prio;
	int (*test_cb)(void);
	int expect_ret;
	/* after running return value */
	int real_ret;

	/* record testing time spend */
	struct timeval start, end;
	suseconds_t spend_us;

	struct list_head node;
	/* if test result is failed, add to 'failed_list' */
	struct list_head failed;
};

extern int nr_tests;

#define TEST_SKIP_RET	0xdead9527

/**
 * Define a test
 * If Ret = TEST_SKIP_RET, the test will success anyway.
 */
#define __TEST(Category, Name, Prio, Ret) \
	extern int test_ ##Category ##_##Name(void);	\
	static void __ctor(Prio) test_ctor_ ##Category ##_##Name(void) {	\
		struct test __unused *test = \
			create_test(#Category, #Name, \
				Prio, test_ ##Category ##_##Name, Ret);	\
	}	\
	int test_ ##Category ##_##Name(void)

/* Highest prio TEST */
#define TEST_HIGHEST(Category, Name, Ret)	\
	__TEST(Category, Name, TEST_PRIO_HIGHEST, Ret)

/* Normal prio TEST */
#define TEST(Category, Name, Ret)	\
	__TEST(Category, Name, TEST_PRIO_MIDDLE, Ret)

/* Lower prio TEST */
#define TEST_LOWER(Category, Name, Ret)	\
	__TEST(Category, Name, TEST_PRIO_LOWER, Ret)

/**
 * ctors in test source code file will not be called by default if you define
 * ctors in static static library, except the function in source code file be
 * called in main() or some other where.
 *
 * FIXME: I don't known why, but it's works for me.
 */
#define TEST_STUB(name) void __test ##name(void) {}
#define CALL_TEST_STUB(name) extern void __test ##name(void); __test ##name();

extern struct list_head test_list[TEST_PRIO_NUM];

extern const char *ulpatch_test_path;

#define TEST_UNIX_PATH	"/tmp/_unix_test_main"


struct test *create_test(char *category, char *name, test_prio prio,
			 int (*cb)(void), int expect_ret);
void release_tests(void);

/* Add wait api */
struct task_wait {
	int msqid;
	char tmpfile[64];
};

struct test_symbol {
	char *sym;
	unsigned long addr;
	enum {
		TYPE_TST_SYM_FUNC,
		TYPE_TST_SYM_DATA,
	} type;
};

extern struct test_symbol test_symbols[];

struct test_symbol *find_test_symbol(const char *sym);
size_t nr_test_symbols(void);


struct clt_msg_hdr {
	enum {
		TEST_MT_REQUEST,
		TEST_MT_RESPONSE,
	} type;

	enum {
		TEST_MC_CLOSE, /* Tell server can close */
		TEST_MC_SYMBOL,
	} code;
};

/**
 * Message between server and client, when ulpatch_test is ROLE_LISTENER
 */
struct clt_msg {
	struct clt_msg_hdr hdr;
	union {
		struct {
			char s[128];
		} symbol_request;
		struct {
			unsigned long addr;
		} symbol_response;
		struct {
		} close_request;
		struct {
			int rslt;
		} close_response;
	} body;
};


int init_listener(void);
void close_listener(void);
void listener_main_loop(void *arg);

int listener_helper_create_test_client(void);
int listener_helper_close_test_client(int fd);
int listener_helper_close(int fd, int *rslt);
int listener_helper_symbol(int fd, const char *sym, unsigned long *addr);

extern void mcount(void);
extern void _mcount(void);

int task_wait_init(struct task_wait *task_wait, char *tmpfile);
int task_wait_destroy(struct task_wait *task_wait);
int task_wait_wait(struct task_wait *task_wait);
int task_wait_trigger(struct task_wait *task_wait);
int task_wait_request(struct task_wait *task_wait, char request,
		      struct msgbuf *rx_buf, size_t rx_buf_size);
int task_wait_response(struct task_wait *task_wait,
		       int (*makemsg)(char request, struct msgbuf *buf,
				      size_t buf_len));

