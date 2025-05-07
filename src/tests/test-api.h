// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/time.h>
#include <sys/msg.h>
#include <setjmp.h>

#include <utils/list.h>
#include <utils/log.h>
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

typedef enum {
	/* constructor priorities from 0 to 100 are reserved for the implementation */
	TEST_PRIO_START = 105,
	TEST_PRIO_HIGHEST,
	TEST_PRIO_HIGHER,
	TEST_PRIO_MIDDLE,
	TEST_PRIO_LOWER,
	TEST_PRIO_NUM = TEST_PRIO_LOWER - TEST_PRIO_START + 1,
} test_prio;

typedef enum {
	TEST_RET_MIN = 0xdead0001,
	TEST_RET_SKIP,
#define TEST_RET_SKIP	TEST_RET_SKIP
	TEST_RET_EMERG,
#define TEST_RET_EMERG	TEST_RET_EMERG
} test_special_ret;

typedef int (*test_function)(void);

/**
 * test entry
 */
struct test {
	int idx;
	char *category;
	char *name;
	test_prio prio;
	test_function test_cb;
	int expect_ret;
	/* after running return value */
	int real_ret;

	/* record testing time spend */
	struct timeval start, end;
	suseconds_t spend_us;

#define TEST_JMP_STATUS	0xff123

#define GOTO_TESTER_AND_SKIP_TEST()	do {	\
		/* Mergency not happen in tests, it's a BUG some where */	\
		if (!current_test) {	\
		      ulp_emerg("Emergency not in test.\n");	\
		      abort();	\
		}	\
		siglongjmp(current_test->jmpbuf, TEST_JMP_STATUS);	\
	} while (0)

	/**
	 * jmpbuf could skip emergency like SIGILL, make ulpatch_test done.
	 *
	 * (4) +---->sighandler() {
	 *     |       SIGSEGV, SIGILL-----+
	 *     |     }                     |
	 *     | +-------------------------+
	 *     | |
	 * (1) | |   execute_one_test() {
	 *     | |                        +-------------------------+
	 * (5) | +----> jmpbuf----------->|real_ret= TEST_RET_EMERG;|(6)
	 *     |                          |goto skip_test;          |
	 *     |                          +-------------------------+
	 * (2) |        current_test() {
	 *     |           +----------------+
	 * (3) +-----------+ SIGSEGV/SIGILL |
	 *                 +----------------+
	 *              }
	 *
	 * (7)       skip_test:
	 *              ...
	 *           }
	 *
	 * Procedures
	 * (1) running a test;
	 * (2) calling callback function;
	 * (3) sigill happen;
	 * (4) signal handler, handle case of signal;
	 * (5) long jump to executer;
	 * (6) set return TEST_RET_EMERG and skip test;
	 * (7) skip this test;
	 */
	sigjmp_buf jmpbuf;

	struct list_head node;
	/* if test result is failed, add to 'failed_list' */
	struct list_head failed;
};

extern int nr_tests;
extern struct test *current_test;

/* see metadata.lds */
#define __TEST_METADATA_SEC	".data.ulpatch.test.metadata"
#define __test_metadata	__section(__TEST_METADATA_SEC)

#define DEFINE_TEST_METADATA(_category, _name, _prio, _func, _ret)		\
	struct test __test_metadata _tmeta_##_category##_name##_prio##_func = {	\
		.category = #_category,						\
		.name = #_name,							\
		.prio = _prio,							\
		.test_cb = _func,						\
		.expect_ret = _ret,						\
		.real_ret = _ret,						\
	};

extern struct test test_meta_start, test_meta_end;

/**
 * Define a test
 * If Ret = TEST_RET_SKIP, the test will success anyway.
 */
#define __TEST(Category, Name, Prio, Ret)					\
	extern int test_ ##Category ##_##Name(void);				\
	DEFINE_TEST_METADATA(Category, Name, Prio, test_ ##Category ##_##Name, Ret);	\
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
#define TEST_STUB(name) void __test_stub_ ##name(void) {}
#define CALL_TEST_STUB(name) extern void __test_stub_ ##name(void); \
		__test_stub_ ##name();

extern struct list_head test_list[TEST_PRIO_NUM];

extern const char *ulpatch_test_path;

#define TEST_UNIX_PATH	"/tmp/_unix_test_main"

void init_tests(void);
struct test *create_test(struct test *test);
void release_tests(void);

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


struct ctrl_msg_hdr {
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
struct ctrl_msg {
	struct ctrl_msg_hdr hdr;
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

/* wait */
struct task_notify {
	int msqid;
	char tmpfile[PATH_MAX];
};

int task_notify_init(struct task_notify *task_notify, char *tmpfile);
int task_notify_destroy(struct task_notify *task_notify);
int task_notify_wait(struct task_notify *task_notify);
int task_notify_trigger(struct task_notify *task_notify);
int task_notify_request(struct task_notify *task_notify, char request,
		      struct msgbuf *rx_buf, size_t rx_buf_size);
int task_notify_response(struct task_notify *task_notify,
		       int (*makemsg)(char request, struct msgbuf *buf,
				      size_t buf_len));

struct ulpatch_object {
#define ULPATCH_OBJ_TYPE_FTRACE	1
#define ULPATCH_OBJ_TYPE_ULP	2
	int type;
	char *path;
};
extern const struct ulpatch_object ulpatch_objs[];
int nr_ulpatch_objs(void);

const char *str_special_ret(test_special_ret val);

/**
 * Test target functions.
 */
void hello_world(void);
