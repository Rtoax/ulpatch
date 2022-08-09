// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdio.h>
#include <patch/patch.h>

#if defined(__x86_64__)
#include "utils/arch/x86_64/mcount.h"
#elif defined(__aarch64__)
#include "utils/arch/aarch64/mcount.h"
#endif


int mcount_entry(unsigned long *parent_loc, unsigned long child,
			struct mcount_regs *regs)
{
	printf("CALL mcount_entry.\n");
	// TODO
	return 0;
}

unsigned long mcount_exit(long *retval)
{
	printf("CALL mcount_exit.\n");
	// TODO
	return 0;
}

#if defined(__x86_64__)
UPATCH_INFO(mcount, ftrace_mcount, "Rong Tao");
#elif defined(__aarch64__)
UPATCH_INFO(_mcount, ftrace__mcount, "Rong Tao");
#endif

