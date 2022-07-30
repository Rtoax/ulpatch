#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <elf/elf_api.h>
#include <patch/patch.h>

#include "test_api.h"

#if defined(__x86_64__)
void my_direct_func(void *arg)
{
	ldebug("Hello. %#0lx\n", my_direct_func);
}

extern void my_tramp(void *);

// see linux:samples/ftrace/ftrace-direct.c
asm (
"	.pushsection    .text, \"ax\", @progbits\n"
"	.type		my_tramp, @function\n"
"	.globl		my_tramp\n"
"   my_tramp:"
"	pushq %rbp\n"
"	movq %rsp, %rbp\n"
"	pushq %rdi\n"
"	call my_direct_func\n"
"	popq %rdi\n"
"	leave\n"
"	ret\n"
"	.size		my_tramp, .-my_tramp\n"
"	.popsection\n"
);

extern void mcount(void);

static void try_to_wake_up(void)
{
	ldebug("TTWU emulate. %#0lx, mcount:%#0lx\n",
		try_to_wake_up, mcount);
}

TEST(Patch,	ftrace_tramp,	0)
{
	try_to_wake_up();

	memshow(try_to_wake_up, MCOUNT_INSN_SIZE * 2);

	// TODO: make ftrace to try_to_wake_up()
#if 0
	unsigned long __unused ip = (unsigned long)try_to_wake_up + MCOUNT_INSN_SIZE + 1;
	unsigned long __unused addr = (unsigned long)my_tramp;
	// *(unsigned long *)ip = addr - (ip - 5);
	*(unsigned long *)ip = addr;
	ldebug("ip:%#0lx addr:%#0lx\n", ip, addr);
#endif

	// call again
	try_to_wake_up();

	return 0;
}
#endif // __x86_64__

