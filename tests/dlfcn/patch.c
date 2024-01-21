#include <stdio.h>

void internal_print_hello(unsigned long ul);

static void patch_internal_print_hello(unsigned long ul)
{
	printf("Hello World. Patched\n");
	/**
	 * Dynamic libraries after dlopen cannot reference symbols in the
	 * original process, but can they be used in other libraries?
	 * I doubt it.
	 */
	internal_print_hello(ul);
}

void patch_print(unsigned long ul)
{
	patch_internal_print_hello(ul);
}

