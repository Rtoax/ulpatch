#include <stdio.h>
#include <ulpatch/meta.h>


extern void internal_print_hello(unsigned long ul);

static void ulpatch_internal_print_hello(unsigned long ul)
{
#if !defined(NO_LIBC)
	printf("Hello World. Patched\n");
#endif
	internal_print_hello(ul);
}

void ulp_print(unsigned long ul)
{
	ulpatch_internal_print_hello(ul);
}
ULPATCH_INFO(ulp_print, print_hello, "Rong Tao");
