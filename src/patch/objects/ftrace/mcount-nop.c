#include <patch/patch.h>


void __visible_default ftrace_mcount_nop(void)
{}

void __visible_default ftrace__mcount_nop(void)
{}

#if defined(__x86_64__)
UPATCH_INFO(mcount, ftrace_mcount, "Rong Tao");
#elif defined(__aarch64__)
UPATCH_INFO(_mcount, ftrace__mcount, "Rong Tao");
#endif

