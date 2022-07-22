#include "util.h"

const char *elftools_arch(void)
{
#if defined(__x86_64__)
	return "x86_64";
#elif defined(__aarch64__)
	return "aarch64";
#else
	return "Unsupport";
#endif
}

const char *elftools_version(void)
{
	return "elftools-0.0.1";
}

