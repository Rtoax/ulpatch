#pragma once

#include <sys/user.h>
#include <sys/syscall.h>

#include "arch/aarch64/instruments.h"

#define SYSCALL_INSTR \
		INST_SYSCALL, /* syscall */\
		INST_INT3, /* int3 */

# define SYSCALL_REGS_PREPARE(_regs, nr, p1, p2, p3, p4, p5, p6)  \
	_regs.regs[8] = (unsigned long)nr;   \
	_regs.regs[0] = p1;  \
	_regs.regs[1] = p2;  \
	_regs.regs[2] = p3;  \
	_regs.regs[3] = p4;  \
	_regs.regs[4] = p5;  \
	_regs.regs[5] = p6;
# define SYSCALL_RET(_regs)   _regs.regs[0]
# define SYSCALL_IP(_regs)    _regs.pc
