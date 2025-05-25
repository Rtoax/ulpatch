/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_DEBUG_MONITORS_H
#define __ASM_DEBUG_MONITORS_H

#include "arch/aarch64/brk-imm.h"

/*
 * BRK instruction encoding
 * The #imm16 value should be placed at bits[20:5] within BRK ins
 */
#define AARCH64_BREAK_MON	0xd4200000

/*
 * BRK instruction for provoking a fault on purpose
 * Unlike kgdb, #imm16 value with unallocated handler is used for faulting.
 */
#define AARCH64_BREAK_FAULT	(AARCH64_BREAK_MON | (FAULT_BRK_IMM << 5))

#endif	/* __ASM_DEBUG_MONITORS_H */
