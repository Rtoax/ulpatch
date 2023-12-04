// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <stdio.h>
#include <unistd.h>


static unsigned long count = 0;

void print_hello(void)
{
	printf("Hello World. %d\n", count);
}

int main(int argc, char *argv[])
{
#define PRINT_ADDR(a)	printf("%-32s: %#016x\n", #a, a);
	PRINT_ADDR(print_hello);
	PRINT_ADDR(puts);

	while (1) {
		print_hello();
		count++;
		sleep(1);
	}

	return 0;
}
