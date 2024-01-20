#include <stdio.h>
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include <ulpatch/meta.h>


void ulp_empty(unsigned long ul)
{
}
ULPATCH_INFO(ulp_empty, print_hello, "Rong Tao");
