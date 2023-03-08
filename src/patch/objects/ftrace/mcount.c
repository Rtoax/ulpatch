// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao */
#include <stdio.h>
#include <patch/patch.h>

#if defined(__x86_64__)
#include "arch/x86_64/mcount.h"
#elif defined(__aarch64__)
#include "arch/aarch64/mcount.h"
#endif


/**
 * The UPATCH_TEST macro just for test in elftoos_test target. it'll not
 * compile into ftrace-object file.
 */
#if defined(UPATCH_TEST)

#include <utils/task.h>
#include <utils/log.h>

extern int try_to_wake_up(struct task *task, int mode, int wake_flags);

#endif /* UPATCH_TEST */


/* for example:
 * main()
 *  -> _ftrace_mcount()
 *    -> mcount_entry()
 */
int mcount_entry(unsigned long *parent_loc, unsigned long child,
			struct mcount_regs *regs)
{
#if defined(UPATCH_TEST)

	lwarning("parent: %p, child: %lx, args: %ld %ld %ld %ld %ld %ld.\n",
		parent_loc,
		child,
		ARG1(regs),
		ARG2(regs),
		ARG3(regs),
		ARG4(regs),
		ARG5(regs),
		ARG6(regs)
	);

	/* This is try_to_wake_up() ftrace, here 0x26 is a emulate value, you can
	 * check the offset with 'objdump -d' command.
	 */
	if (child - (unsigned long)try_to_wake_up > 0x0 &&
		child - (unsigned long)try_to_wake_up < 0x26) {
		struct task *task = (void *)ARG1(regs);
		lwarning("COMM: %s, PID %d\n", task->comm, task->pid);
	}

#endif /* UPATCH_TEST */

	// TODO
	return 0;
}

unsigned long mcount_exit(long *retval)
{
#if defined(UPATCH_TEST)
	printf("CALL mcount_exit.\n");

#endif /* UPATCH_TEST */

	// TODO
	return 0;
}

#if defined(__x86_64__)
UPATCH_INFO(uftrace, mcount, _ftrace_mcount, "Rong Tao");
#elif defined(__aarch64__)
UPATCH_INFO(uftrace, _mcount, _ftrace_mcount, "Rong Tao");
#endif

