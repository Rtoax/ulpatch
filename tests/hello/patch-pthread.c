#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include <ulpatch/meta.h>

extern void internal_print_hello(unsigned long ul);

int created = false;
pthread_t thread = { 0 };

void *routine(void *arg)
{
	while (1) {
		printf("hello from patch thread.\n");
		sleep(1);
	}
}

void ulpatch_print_hello_print(unsigned long ul)
{
	if (!created) {
		printf("Hello World. Patched\n");
		created = true;
		pthread_create(&thread, NULL, routine, NULL);
	}
	internal_print_hello(ul);
}
ULPATCH_INFO(ulpatch, ulpatch_print_hello_print, print_hello, "Rong Tao");
