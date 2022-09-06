// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>

#include <elf/elf_api.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>

#include "elf-usdt.h"

#define MAX_EVENTS 10
#define MAX_CLIENT 10

static int listenfd;
static pthread_t thread;
static int main_epollfd = -1;
static pthread_mutex_t epoll_mutex = PTHREAD_MUTEX_INITIALIZER;

/* client list head */
LIST_HEAD(client_list);
unsigned int nr_clients = 0;

int elf_load_handler(struct client*, struct cmd_elf *);
int elf_delete_handler(struct client*, struct cmd_elf *);
int elf_list_handler(struct client*, struct cmd_elf *);
int elf_list_handler_ack(struct client*, struct cmd_elf *);
int elf_select_handler(struct client*, struct cmd_elf *);
int elf_get_ehdr_handler(struct client*, struct cmd_elf *);
int elf_get_ehdr_handler_ack(struct client *, struct cmd_elf *);
int elf_get_phdr_handler(struct client*, struct cmd_elf *);
int elf_get_phdr_handler_ack(struct client*, struct cmd_elf *);
int elf_get_shdr_handler(struct client*, struct cmd_elf *);
int elf_get_shdr_handler_ack(struct client*, struct cmd_elf *);
int elf_get_syms_handler(struct client*, struct cmd_elf *);
int elf_get_syms_handler_ack(struct client*, struct cmd_elf *);
int register_client_handler(struct client*, struct cmd_elf *);
int list_client_handler(struct client*, struct cmd_elf *);
int list_client_handler_ack(struct client*, struct cmd_elf *);
int test_server_handler(struct client*, struct cmd_elf *);
int test_server_handler_ack(struct client*, struct cmd_elf *);

int send_one_ack(struct client *client, struct cmd_elf *cmd_ack)
{
	int ret =  write(client->info.connfd, cmd_ack, cmd_len(cmd_ack));

	memset(cmd_ack, 0x0, cmd_len(cmd_ack));

	return ret;
}

int client_recv_acks(int connfd, int (*handler)(struct cmd_elf *msg_ack))
{
	assert(handler && "must have handler()");

	int ret = 0;
	int buffer_idx = 0;
	char buffer[BUFFER_SIZE];
	uint32_t __unused nbytes;
	char __unused *pbuf = NULL;
	uint32_t total_nbytes = 0;

	struct cmd_elf *cmd_ack;
	struct cmd_elf_ack *ack;

	/**
	 * if
	 *  BUFFER_SIZE = 8
	 *  msg_len = 3
	 *  need to read: abcdefghijklmnopqrstuvwxyz
	 *
	 * Start
	 *  read 1st
	 *    buffer: abcdefgh
	 *      parse:
	 *        msg1: abc
	 *        msg2: def
	 *        left: gh
	 *        buffer_idx: 2
	 *        buffer: gh--------
	 *
	 *  read 2nd
	 *    buffer: ghijklmn
	 *      parse:
	 *        msg1: ghi
	 *        msg2: jkl
	 *        left: mn
	 *        buffer_idx: 2
	 *        buffer: mn--------
	 *
	 *  ...
	 */
read_again:
	nbytes = read(connfd, buffer + buffer_idx, sizeof(buffer) - buffer_idx);
	nbytes += buffer_idx;
	total_nbytes += nbytes;
	pbuf = buffer;
	buffer_idx = 0;

parse_again:
	cmd_ack = (struct cmd_elf *)pbuf;
	ack = cmd_data(cmd_ack);
	if (ack->result != 0) {
		lerror("bad ack.\n");
	}

	/* Call ack handler callback */
	int handler_ret = handler(cmd_ack);
	if (handler_ret != 0)
		ret = handler_ret;

	/* write(2) may combine send buffer, split it */
	uint32_t msg_len = cmd_len(cmd_ack);
	if (nbytes >= msg_len) {
		pbuf += msg_len;
		nbytes -= msg_len;

		if (nbytes > 0) {
			// Each message length not equal to each other, we need to update
			// `msg_len` here.
			if (nbytes > sizeof(struct cmd_elf)) {
				msg_len = cmd_len((struct cmd_elf*)pbuf);
			}
			if (nbytes < msg_len) {
				buffer_idx = nbytes;
				memcpy(buffer, pbuf, nbytes);

				goto read_again;
			} else {
				goto parse_again;
			}
		} else if (nbytes == 0) {
			goto return_and_check;
		}
	} else {
		lerror("nbytes(%d) < msg_len(%d)\n", nbytes, msg_len);
	}

return_and_check:
	if (cmd_ack->has_next) {
		//lwarning("has_next.\n");
		goto read_again;
	}

	return ret;
}

static unsigned long int all_cmd_stat[CMD_MAX__] = {};
static struct cmd_handler cmd_handlers[CMD_MAX__] = {
	[CMD_ELF_LOAD] = {CMD_ELF_LOAD, elf_load_handler, NULL},
	[CMD_ELF_DELETE] = {CMD_ELF_DELETE, elf_delete_handler, NULL},
	[CMD_ELF_LIST] = {CMD_ELF_LIST, elf_list_handler, elf_list_handler_ack},
	[CMD_ELF_SELECT] = {CMD_ELF_SELECT, elf_select_handler, NULL},
	[CMD_ELF_GET_EHDR] = {CMD_ELF_GET_EHDR, elf_get_ehdr_handler, elf_get_ehdr_handler_ack},
	[CMD_ELF_GET_PHDR] = {CMD_ELF_GET_PHDR, elf_get_phdr_handler, elf_get_phdr_handler_ack},
	[CMD_ELF_GET_SHDR] = {CMD_ELF_GET_SHDR, elf_get_shdr_handler, elf_get_shdr_handler_ack},
	[CMD_ELF_GET_SYMS] = {CMD_ELF_GET_SYMS, elf_get_syms_handler, elf_get_syms_handler_ack},
	[CMD_REGISTER_CLIENT] = {CMD_REGISTER_CLIENT, register_client_handler, NULL},
	[CMD_LIST_CLIENT] = {CMD_LIST_CLIENT, list_client_handler, list_client_handler_ack},
	[CMD_TEST_SERVER] = {CMD_TEST_SERVER, test_server_handler, test_server_handler_ack},
};

void handle_client_msg(struct client *client)
{
	enum cmd_type cmd;
	struct cmd_elf *cmd_msg;
	struct cmd_elf *cmd_ack;
	struct cmd_elf_ack *ack;
	ssize_t __unused size;
	char buffer[BUFFER_SIZE] = {};
	int ret = -1;

	/* Recv request */
	size = read(client->info.connfd, buffer, sizeof(buffer));
	cmd_msg = (struct cmd_elf *)buffer;
	cmd = cmd_msg->cmd;

	if (cmd >= CMD_MAX__ || cmd <= CMD_MIN__) {
		lerror("Invalid command %d\n", cmd);
		return;
	}
	client->cmd_stat[cmd]++;
	all_cmd_stat[cmd]++;

	/* Start to handle msg */
	trace_elf_handle_msg_start(cmd);

	/* Call handler */
	if (cmd_handlers[cmd].handler)
		ret = cmd_handlers[cmd].handler(client, cmd_msg);

	/* Send ACK */
	cmd_ack = (struct cmd_elf *)buffer;
	cmd_ack->cmd = cmd;
	cmd_ack->is_ack = 1;
	cmd_ack->has_next = 0; // default no next
	cmd_ack->data_len = sizeof(struct cmd_elf_ack);

	ack = cmd_data(cmd_ack);
	// No need to set '_errno', because is union with 'result'
	ack->result = ret;

	/* Call ack handler */
	if (cmd_handlers[cmd].ack)
		ret = cmd_handlers[cmd].ack(client, cmd_ack);
	else ret = send_one_ack(client, cmd_ack);

	/* End to handle msg */
	trace_elf_handle_msg_end(cmd);

	return;
}

void *elf_thread(void *arg)
{
	int i, ret, nfds;
	struct epoll_event events[MAX_EVENTS];
	static sigset_t sigmask;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGUSR1);

	for (;;) {
		nfds = epoll_wait(main_epollfd, events, MAX_EVENTS, -1);
		if (nfds == -1) {
			lerror("epoll_wait: %s\n", strerror(errno));
			continue;
		}
		for (i = 0; i < nfds; i++) {
			struct epoll_event *event = &events[i];

			/* Add a new client */
			if (event->data.fd == listenfd) {
				struct epoll_event event;
				socklen_t len = sizeof(struct sockaddr_un);
				struct client *client = malloc(sizeof(struct client));

				memset(client, 0x0, sizeof(struct client));

				client->info.connfd = accept(listenfd,
					(struct sockaddr*)&client->addr, &len);

				/* Add new client to epoll */
				event.events = EPOLLIN;
				event.data.fd = client->info.connfd;

				ret = epoll_ctl(main_epollfd, EPOLL_CTL_ADD,
							client->info.connfd, &event);
				if (ret == -1) {
					lerror("cannot add fd to epoll, %s\n", strerror(errno));
					free(client);
					continue;
				}
				list_add(&client->node, &client_list);
				nr_clients++;

			/* Handle all client */
			} else {
				struct client *client, *tmp;

				list_for_each_entry_safe(client, tmp, &client_list, node) {
					if (client->info.connfd == event->data.fd) {
						/* Client close */
						if (event->events & EPOLLHUP) {
							close(client->info.connfd);

							epoll_ctl(main_epollfd, EPOLL_CTL_DEL,
								client->info.connfd, NULL);

							list_del(&client->node);
							free(client);
							nr_clients--;

						/* Handle a client */
						} else if (event->events & EPOLLIN) {
							handle_client_msg(client);
						}
					}
				}
			}
		}
	}
}

static void sig_handler(int signum)
{
	pthread_exit(NULL);
}

int elf_main(int argc, char *argv[])
{
	int ret = 0;
	struct epoll_event event;
	struct sockaddr_un srv_addr;

	signal(SIGUSR1, sig_handler);

	pthread_mutex_lock(&epoll_mutex);
	if (main_epollfd != -1) {
		lwarning("already called elf_main()\n");
		pthread_mutex_unlock(&epoll_mutex);
		return -EPERM; /* Operation not permitted */
	}
	main_epollfd = epoll_create(1);
	assert(main_epollfd != -1 && "epoll_create failed.\n");
	pthread_mutex_unlock(&epoll_mutex);

	/* Create unix domain socket */
	listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listenfd < 0) {
		ret = -errno;
		lerror("create listening socket error, %s\n", strerror(errno));
		return ret;
	}
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, NULL, 0);

	if (fexist(ELF_UNIX_PATH) && (ret = unlink(ELF_UNIX_PATH))) {
		lerror("unlink(%s) failed, %s\n", ELF_UNIX_PATH, strerror(errno));
		close(main_epollfd);
		close(listenfd);
		return -errno;
	}

	srv_addr.sun_family = AF_UNIX;
	strncpy(srv_addr.sun_path, ELF_UNIX_PATH, sizeof(srv_addr.sun_path) - 1);
	ret = bind(listenfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (ret == -1) {
		ret = -errno;
		lerror("cannot bind server socket, %s\n", strerror(errno));
		close(main_epollfd);
		close(listenfd);
		unlink(ELF_UNIX_PATH);
		return ret;
	}
	ret = listen(listenfd, MAX_CLIENT);

	event.events = EPOLLIN;
	event.data.fd = listenfd;
	ret = epoll_ctl(main_epollfd, EPOLL_CTL_ADD, listenfd, &event);
	if (ret == -1) {
		ret = -errno;
		lerror("cannot add listendfd to epoll, %s\n", strerror(errno));
		close(main_epollfd);
		close(listenfd);
		unlink(ELF_UNIX_PATH);
		return ret;
	}

	ret = pthread_create(&thread, NULL, elf_thread, NULL);
	if (ret != 0) {
		lerror("create listend thread failed.\n");
		close(main_epollfd);
		close(listenfd);
		unlink(ELF_UNIX_PATH);
		exit(1);
	}
	pthread_setname_np(thread, "elf-main");
	pthread_setname_np(pthread_self(), "upatch-server");

	return 0;
}

void elf_exit(void)
{
	struct client *client, *tmp;

	pthread_kill(thread, SIGUSR1);
	pthread_join(thread, NULL);

	list_for_each_entry_safe(client, tmp, &client_list, node) {
		list_del(&client->node);
		free(client);
		nr_clients--;
	}
}

