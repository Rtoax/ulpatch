// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <malloc.h>
#include <string.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/task.h>

#include "test_api.h"

int nr_tests = 0;


struct test*
create_test(char *category, char *name, test_prio prio, int (*cb)(void),
	int expect_ret)
{
	struct test *test = malloc(sizeof(struct test));

	test->idx = ++nr_tests;
	test->category = strdup(category);
	test->name = strdup(name);
	test->prio = prio;
	test->test_cb = cb;
	test->expect_ret = expect_ret;

	list_add(&test->node, &test_list[prio - TEST_PRIO_START]);

	return test;
}

void release_tests(void)
{
	int i;
	struct test *test, *tmp;

	/* for each priority */
	for (i = 0; i < TEST_PRIO_NUM; i++) {
		/* for each test entry */
		list_for_each_entry_safe(test, tmp, &test_list[i], node) {
			list_del(&test->node);
			free(test->category);
			free(test->name);
			free(test);
		}
	}
}


#define PROG_ID	123
#define MSG_TYPE_WAIT_TRIGGER	1
#define MSG_TYPE_REQUEST	2
#define MSG_TYPE_RESPONSE	3


static int create_msqid(const char *file)
{
	int msqid;
	key_t key;

	while (!fexist(file));

	if ((key = ftok(file, PROG_ID)) < 0) {
		perror("ftok error");
		return -1;
	}

	if ((msqid = msgget(key, IPC_CREAT | 0777)) == -1) {
		perror("msgget error");
		return -1;
	}

	return msqid;
}

/* key: ftok(2) open/create a tmp file
 */
int task_wait_init(struct task_wait *task_wait, char *tmpfile)
{
	if (tmpfile)
		snprintf(task_wait->tmpfile, sizeof(task_wait->tmpfile), tmpfile);
	else
		fmktempfile(task_wait->tmpfile, sizeof(task_wait->tmpfile), NULL);

	return 0;
}

int task_wait_destroy(struct task_wait *task_wait)
{
	msgctl(task_wait->msqid, IPC_RMID, NULL);
	unlink(task_wait->tmpfile);
	return 0;
}

int task_wait_wait(struct task_wait *task_wait)
{
	int ret;
	int msqid = create_msqid(task_wait->tmpfile);

	struct msgbuf msg;

recv:
	ret = msgrcv(msqid, &msg, sizeof(msg.mtext), MSG_TYPE_WAIT_TRIGGER, 0);
	if (ret == -1) {
		if (errno != ENOMSG) {
			perror("msgrcv");
		} else {
			goto recv;
		}
	}
	/**
	 * Just wait some time, make sure the message not combian to each other
	 * int msgqueue.
	 */
	usleep(10000);

	return 0;
}

int task_wait_trigger(struct task_wait *task_wait)
{
	int ret = 0;
	int msqid = create_msqid(task_wait->tmpfile);

	struct msgbuf msg = {
		.mtype = MSG_TYPE_WAIT_TRIGGER,
		.mtext = {0},
	};

	msg.mtext[0] = 'q';

	ret = msgsnd(msqid, &msg, sizeof(msg.mtext), 0);
	if (ret < 0) {
		fprintf(stderr, "%d = msgsnd(%d) failed, %s.\n",
			ret, msqid, strerror(errno));
	}
	/* SAME as usleep() in task_wait_wait() */
	usleep(10000);

	return 0;
}

#if defined(ldebug)
#undef ldebug
#define ldebug(...)
#endif

int task_wait_request(struct task_wait *task_wait, char request,
	struct msgbuf *rx_buf, size_t rx_buf_size)
{
	int ret;
	int msqid = create_msqid(task_wait->tmpfile);

	struct msgbuf msg = {
		.mtype = MSG_TYPE_REQUEST,
		.mtext[0] = request,
	};
	ldebug("TX request: %d, start\n", request);

	ret = msgsnd(msqid, &msg, sizeof(msg.mtext), 0);
	if (ret < 0) {
		fprintf(stderr, "%d = msgsnd(%d) failed, %s.\n",
			ret, msqid, strerror(errno));
	}

	ldebug("TX request: %d\n", request);

recv:
	ret = msgrcv(msqid, rx_buf, rx_buf_size - sizeof(long),
			MSG_TYPE_RESPONSE, 0);
	if (ret == -1) {
		if (errno != ENOMSG) {
			perror("msgrcv");
		} else {
			goto recv;
		}
	}
	ldebug("RX response: %d\n", request);

	return 0;
}

/*
 * @makemsg create msgbuf, return msg text length
 */
int task_wait_response(struct task_wait *task_wait,
	int (*makemsg)(char request, struct msgbuf *buf, size_t buf_len))
{
	int ret, len;
	int msqid = create_msqid(task_wait->tmpfile);
	char buffer[BUFFER_SIZE];
	struct msgbuf msg, *pmsg;

	ldebug("RX request: %d, start\n");
recv:
	ret = msgrcv(msqid, &msg, sizeof(msg.mtext), MSG_TYPE_REQUEST, 0);
	if (ret == -1) {
		if (errno != ENOMSG) {
			perror("msgrcv");
		} else {
			goto recv;
		}
	}
	ldebug("RX request: %d\n", msg.mtext[0]);

	pmsg = (struct msgbuf *)buffer;

	len = makemsg(msg.mtext[0], pmsg, BUFFER_SIZE);

	pmsg->mtype = MSG_TYPE_RESPONSE;
	pmsg->mtext[0] = msg.mtext[0];

	ret = msgsnd(msqid, pmsg, len, 0);
	if (ret < 0) {
		fprintf(stderr, "%d = msgsnd(%d) failed, %s.\n",
			ret, msqid, strerror(errno));
	}
	ldebug("TX response: %d\n", msg.mtext[0]);

	return 0;
}

