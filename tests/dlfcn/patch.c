#include <stdio.h>

void internal_print_hello(unsigned long ul);

static int a;
static char *s = "Hello";

static void patch_internal_print_hello(unsigned long ul)
{
	a++;
	printf("Hello World. %s Patched %d\n", s, a);

#if defined(TEST_TARGET_SYMBOL)
	/**
	 * Dynamic libraries after dlopen cannot reference symbols in the
	 * original process, but can they be used in other libraries?
	 * I doubt it.
	 */
	internal_print_hello(ul);
#endif
}

void patch_print(unsigned long ul)
{
	patch_internal_print_hello(ul);
}

