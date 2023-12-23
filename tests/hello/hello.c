// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <stdio.h>
#include <unistd.h>


static unsigned long count = 0;

void internal_print_hello(unsigned long ul)
{
	printf("Hello World. %d, %ld\n", count, ul);
}

void print_hello(unsigned long ul)
{
	internal_print_hello(ul);
}

int main(int argc, char *argv[])
{
	unsigned long ul = 0xff;

#define PRINT_ADDR(a)	printf("%-32s: %#016x\n", #a, a);
	PRINT_ADDR(print_hello);
	PRINT_ADDR(puts);

	while (1) {
		print_hello(ul);
		count++;
		sleep(2);
	}

	return 0;
}
