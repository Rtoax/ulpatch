// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdio.h>
#include <patch/patch.h>

#if defined(__x86_64__)
#include "utils/arch/x86_64/mcount.h"
#elif defined(__aarch64__)
#include "utils/arch/aarch64/mcount.h"
#endif


/* The ELFTOOLS_TEST macro just for test in elftoos_test target. it'll not
 * compile into ftrace-object file.
 */
#if defined(ELFTOOLS_TEST)

#include <utils/task.h>
#include <utils/log.h>

extern int try_to_wake_up(struct task *task, int mode, int wake_flags);

#endif /* ELFTOOLS_TEST */


/* for example:
 * main()
 *  -> _ftrace_mcount()
 *    -> mcount_entry()
 */
int mcount_entry(unsigned long *parent_loc, unsigned long child,
			struct mcount_regs *regs)
{
#if defined(ELFTOOLS_TEST)

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

#endif /* ELFTOOLS_TEST */

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

