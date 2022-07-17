#pragma once

#include <sys/user.h>
#include <sys/syscall.h>

#include "arch/x86_64/instruments.h"

#define SYSCALL_INSTR \
		INST_SYSCALL, /* syscall */\
		INST_INT3, /* int3 */

#define SYSCALL_REGS_PREPARE(regs, nr, p1, p2, p3, p4, p5, p6)  \
        regs.rax = (unsigned long)nr;   \
        regs.rdi = p1;  \
        regs.rsi = p2;  \
        regs.rdx = p3;  \
        regs.r10 = p4;  \
        regs.r8 = p5;   \
        regs.r9 = p6;
#define SYSCALL_RET(regs)   regs.rax
#define SYSCALL_IP(regs)    regs.rip
