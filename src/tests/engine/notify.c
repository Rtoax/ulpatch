// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <malloc.h>
#include <string.h>

#include "utils/log.h"
#include "utils/list.h"
#include "task/task.h"

#include "tests/test-api.h"


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

/* key: ftok(2) open/create a tmp file */
int task_notify_init(struct task_notify *task_notify, char *tmpfile)
{
	if (tmpfile)
		snprintf(task_notify->tmpfile, sizeof(task_notify->tmpfile), "%s",
			 tmpfile);
	else
		fmktempfile(task_notify->tmpfile, sizeof(task_notify->tmpfile),
			    NULL);
	return 0;
}

int task_notify_destroy(struct task_notify *task_notify)
{
	msgctl(task_notify->msqid, IPC_RMID, NULL);
	unlink(task_notify->tmpfile);
	return 0;
}

int task_notify_wait(struct task_notify *task_notify)
{
	int ret;
	int msqid = create_msqid(task_notify->tmpfile);

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

int task_notify_trigger(struct task_notify *task_notify)
{
	int ret = 0;
	int msqid = create_msqid(task_notify->tmpfile);

	struct msgbuf msg = {
		.mtype = MSG_TYPE_WAIT_TRIGGER,
		.mtext = {0},
	};

	msg.mtext[0] = 'q';

	ret = msgsnd(msqid, &msg, sizeof(msg.mtext), 0);
	if (ret < 0) {
		ulp_error("%d = msgsnd(%d) failed, %m.\n", ret, msqid);
	}
	/* SAME as usleep() in task_notify_wait() */
	usleep(10000);

	return 0;
}

#if defined(ulp_debug)
#undef ulp_debug
#define ulp_debug(...)
#endif

int task_notify_request(struct task_notify *task_notify, char request,
		      struct msgbuf *rx_buf, size_t rx_buf_size)
{
	int ret;
	int msqid = create_msqid(task_notify->tmpfile);

	struct msgbuf msg = {
		.mtype = MSG_TYPE_REQUEST,
		.mtext[0] = request,
	};
	ulp_debug("TX request: %d, start\n", request);

	ret = msgsnd(msqid, &msg, sizeof(msg.mtext), 0);
	if (ret < 0) {
		ulp_error("%d = msgsnd(%d) failed, %m.\n", ret, msqid);
	}

	ulp_debug("TX request: %d\n", request);

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
	ulp_debug("RX response: %d\n", request);

	return 0;
}

/*
 * @makemsg create msgbuf, return msg text length
 */
int task_notify_response(struct task_notify *task_notify,
		       int (*makemsg)(char request, struct msgbuf *buf,
			size_t buf_len))
{
	int ret, len;
	int msqid = create_msqid(task_notify->tmpfile);
	char buffer[BUFFER_SIZE];
	struct msgbuf msg, *pmsg;

	ulp_debug("RX request: %d, start\n");
recv:
	ret = msgrcv(msqid, &msg, sizeof(msg.mtext), MSG_TYPE_REQUEST, 0);
	if (ret == -1) {
		if (errno != ENOMSG) {
			perror("msgrcv");
		} else {
			goto recv;
		}
	}
	ulp_debug("RX request: %d\n", msg.mtext[0]);

	pmsg = (struct msgbuf *)buffer;

	len = makemsg(msg.mtext[0], pmsg, BUFFER_SIZE);

	pmsg->mtype = MSG_TYPE_RESPONSE;
	pmsg->mtext[0] = msg.mtext[0];

	ret = msgsnd(msqid, pmsg, len, 0);
	if (ret < 0) {
		ulp_error("%d = msgsnd(%d) failed, %m.\n", ret, msqid);
	}
	ulp_debug("TX response: %d\n", msg.mtext[0]);

	return 0;
}
