#include <stdio.h>

#include <patch/patch.h>

#define __visible_default  __attribute__((visibility("default")))

#define print_func() printf("[%s:%d]\n", __func__, __LINE__)


void __visible_default ftrace_mcount(void)
{
	print_func();
}

void __visible_default ftrace__mcount(void)
{
	print_func();
}

#if defined(__x86_64__)
UPATCH_INFO(mcount, ftrace_mcount, "Rong Tao");
#elif defined(__aarch64__)
UPATCH_INFO(_mcount, ftrace__mcount, "Rong Tao");
#endif

