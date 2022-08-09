// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#ifndef __ELF_UPATCH_H
#define __ELF_UPATCH_H 1

#include <stdbool.h>

#include <utils/util.h>
#include <utils/compiler.h>

#include <patch/meta.h>


#if defined(__x86_64__)
#include <utils/arch/x86_64/instruments.h>
#include <utils/arch/x86_64/mcount.h>
#elif defined(__aarch64__)
#include <utils/arch/aarch64/instruments.h>
#include <utils/arch/aarch64/mcount.h>
#include <utils/arch/aarch64/ftrace.h>
#endif


/* ftrace */
#if defined(__x86_64__)
# define MCOUNT_INSN_SIZE	CALL_INSN_SIZE
#elif defined(__aarch64__)
/* A64 instructions are always 32 bits. */
# define MCOUNT_INSN_SIZE	BL_INSN_SIZE
#endif


bool is_ftrace_entry(char *func);

extern void _ftrace_mcount(void);
extern void _ftrace_mcount_return(void);

int mcount_entry(unsigned long *parent_loc, unsigned long child,
			struct mcount_regs *regs);
unsigned long mcount_exit(long *retval);


#endif /* __ELF_UPATCH_H */

