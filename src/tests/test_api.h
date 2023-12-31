// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
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
	int test_ ##Category ##_##Name(void);	\
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

extern struct list_head test_list[TEST_PRIO_NUM];

extern const char *ulpatch_test_path;


#ifdef PRINTER_FN
# error "Redefine PRINTER_FN"
#endif
#define PRINTER_FN	print_hello
int PRINTER_FN(int nloop, const char *content);


#define LIBC_PUTS_FN	puts

#define TEST_UNIX_PATH	"/tmp/_unix_test_main"


struct test*
create_test(char *category, char *name, test_prio prio, int (*cb)(void),
	int expect_ret);
void release_tests(void);

/* Add wait api */
struct task_wait {
	int msqid;
	char tmpfile[64];
};

struct test_symbol {
	char *sym;
	/* store alias, for example:
	 * 'stdout' is '_IO_2_1_stdout_' in libc. */
	char *alias;
	unsigned long addr;
	enum {
		TST_NON_STATIC,
		TST_DYNSYM,
		TST_SELF_SYM,
	} type;
};

static struct test_symbol __unused test_symbols[] = {
#define TEST_SYM_NON_STATIC(s, a) { \
		.sym = __stringify(s), \
		.alias = __stringify(a), \
		.addr = 0, \
		.type = TST_NON_STATIC \
	},
#define TEST_DYNSYM(s) { __stringify(s), 0, .type = TST_DYNSYM},
#define TEST_SYM_SELF(s) { __stringify(s), 0, .type = TST_SELF_SYM},
#include "test_symbols.h"
#undef TEST_DYNSYM
#undef TEST_SYM_SELF
#undef TEST_SYM_NON_STATIC
};

struct test_symbol * find_test_symbol(const char *sym);


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
	int (*makemsg)(char request, struct msgbuf *buf, size_t buf_len));

