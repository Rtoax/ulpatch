// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#pragma once

#include <sys/user.h>
#include <sys/syscall.h>


#define SYSCALL_REGS_PREPARE(regs, nr, p1, p2, p3, p4, p5, p6) do {	\
		regs.regs[8] = (unsigned long)nr;	\
		regs.regs[0] = p1;	\
		regs.regs[1] = p2;	\
		regs.regs[2] = p3;	\
		regs.regs[3] = p4;	\
		regs.regs[4] = p5;	\
		regs.regs[5] = p6;	\
	} while (0)

#define SYSCALL_RET(regs)	regs.regs[0]
#define SYSCALL_IP(regs)	regs.pc
