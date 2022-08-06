#include <stdio.h>

#include <patch/patch.h>

#define __visible_default  __attribute__((visibility("default")))

#define print_func() printf("[%s:%d]\n", __func__, __LINE__)


void __visible_default mcount(void)
{
	print_func();
}

void __visible_default _mcount(void)
{
	print_func();
}

