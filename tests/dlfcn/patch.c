// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#include <stdio.h>
#include <pthread.h>


static int a;
static char *s = "Hello";
int global_a;
char *global_s = "Hello";

static void *routine(void *arg)
{
	printf("thread %lx\n", pthread_self());
	return NULL;
}

static void patch_internal_print_hello(unsigned long ul)
{
	pthread_t thread;
	a++;
	printf("Hello World. %s Patched %d\n", s, a);

#if defined(TEST_TARGET_SYMBOL)
	void internal_print_hello(unsigned long ul);
	/**
	 * Dynamic libraries after dlopen cannot reference symbols in the
	 * original process, but can they be used in other libraries?
	 * I doubt it.
	 */
	internal_print_hello(ul);
#endif
	pthread_create(&thread, NULL, routine, NULL);
	pthread_join(thread, NULL);
}

void patch_print(unsigned long ul)
{
	patch_internal_print_hello(ul);
}

