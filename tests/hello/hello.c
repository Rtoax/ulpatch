// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#ifdef WITH_DLOPEN_TEST
#include <dlfcn.h>
#endif
#include <limits.h>
#include <unistd.h>
#include <errno.h>

static sig_atomic_t keep_running = true;
static unsigned long count = 0;

/* Some global variable for testing */
int global_i = 1;
char global_c = '\0';
float global_f = 3.14;

#ifdef WITH_DLOPEN_TEST
typedef void (*print_hello_fn)(unsigned long);

static print_hello_fn patch_hello;

int load_patch_so(void)
{
	void *dp;

	dp = dlopen("./patch.so", RTLD_LAZY);
	if (!dp) {
		printf("ERROR: Failed open patch.so.\n");
		exit(1);
	}
	patch_hello = dlsym(dp, "patch_print");
	if (!patch_hello) {
		printf("ERROR: not found patch_print in patch.so.\n");
		exit(1);
	}
}
#endif

void sig_handler(int sig)
{
	switch (sig) {
	case SIGINT:
		printf("Catch ctrl-C.\n");
		keep_running = false;
		break;
	}
}

/**
 * This maybe use to test 'ultash --jmp ...'
 */
void patch_hello2(unsigned long ul)
{
	printf("Hello World. %ld, %ld, patched\n", count, ul);
}

void internal_print_hello(unsigned long ul)
{
#ifdef WITH_DLOPEN_TEST
	void print_hello(unsigned long ul);
	printf("Hello World. %d, %ld, %lx, %lx\n", count, ul,
		(unsigned long)print_hello,
		(unsigned long)patch_hello);
#else
	printf("Hello World. %ld, %ld\n", count, ul);
#endif
}

void print_hello(unsigned long ul)
{
	internal_print_hello(ul);
}

/**
 * What if there are lots of same symbols name, which one should we choise
 * to as relocate resolve symbol.
 */
void *hello_routine(void *arg)
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
	char buf[PATH_MAX];
	pthread_t threads[NR_THREADS];

	signal(SIGINT, sig_handler);

	snprintf(buf, PATH_MAX, "cat /proc/%d/maps", getpid());
	system(buf);

#ifdef WITH_DLOPEN_TEST
	load_patch_so();
#endif

#define PRINT_ADDR(a)	printf("%-32s: %#016lx\n", #a, (unsigned long)a);
	PRINT_ADDR(print_hello);
	PRINT_ADDR(patch_hello2);
	PRINT_ADDR(puts);
	PRINT_ADDR(sleep);
	PRINT_ADDR(pthread_create);
	PRINT_ADDR(internal_print_hello);
	PRINT_ADDR(&errno);

	for (i = 0; i < NR_THREADS; i++)
		pthread_create(&threads[i], NULL, hello_routine, NULL);

	for (i = 0; i < NR_THREADS; i++)
		pthread_join(threads[i], NULL);

	return 0;
}

