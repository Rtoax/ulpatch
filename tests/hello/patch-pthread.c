// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <ulpatch/meta.h>

extern void internal_print_hello(unsigned long ul);

int not_created = true;
pthread_t thread = { 1 };

/**
 * This patch test is not support unpatch(segvfault), because when unpatch, the
 * pthread callback in ulp vma, after unpatch, the routine() is not exist.
 *
 * FIXME: See docs/TODO.
 */
void *routine(void *arg)
{
	while (1) {
		printf("hello from patch thread.\n");
		sleep(1);
	}
}

void ulp_pthread(unsigned long ul)
{
	if (not_created) {
		printf("Hello World. Patched\n");
		not_created = false;
		pthread_create(&thread, NULL, routine, NULL);
	}
	internal_print_hello(ul);
}
ULPATCH_INFO(ulp_pthread, print_hello, "Rong Tao");
