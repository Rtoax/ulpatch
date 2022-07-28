#include <stdio.h>

#include <patch/patch.h>

__ftrace_data
int i1 = 1;

__ftrace_text
void f1(void)
{
	printf("i1 = %d\n", i1);
}


PATCH_AUTHOR("Rong Tao");

