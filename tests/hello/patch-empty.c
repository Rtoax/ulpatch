#include <stdio.h>
#ifndef __ULP_DEV
#define __ULP_DEV
#endif
#include <ulpatch/meta.h>


void ulpatch_print_hello(unsigned long ul)
{
}
ULPATCH_INFO(ulpatch, ulpatch_print_hello, print_hello, "Rong Tao");
