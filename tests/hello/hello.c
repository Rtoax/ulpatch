// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>

static sig_atomic_t keep_running = true;
static unsigned long count = 0;

void sig_handler(int sig)
{
	switch (sig) {
	case SIGINT:
		printf("Catch ctrl-C.\n");
		keep_running = false;
		break;
	}
}

void internal_print_hello(unsigned long ul)
{
	printf("Hello World. %d, %ld\n", count, ul);
}

void print_hello(unsigned long ul)
{
	internal_print_hello(ul);
}

void *routine(void *arg)
{
	unsigned long ul = 0xff;

	while (keep_running) {
		print_hello(ul);
		count++;
		sleep(2);
	}
	return NULL;
}

#define NR_THREADS	3

int main(int argc, char *argv[])
{
	int i;
	pthread_t threads[NR_THREADS];

	signal(SIGINT, sig_handler);

#define PRINT_ADDR(a)	printf("%-32s: %#016x\n", #a, a);
	PRINT_ADDR(print_hello);
	PRINT_ADDR(puts);

	for (i = 0; i < NR_THREADS; i++)
		pthread_create(&threads[i], NULL, routine, NULL);

	for (i = 0; i < NR_THREADS; i++)
		pthread_join(threads[i], NULL);

	return 0;
}
