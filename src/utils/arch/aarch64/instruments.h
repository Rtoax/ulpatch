// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#pragma once

#include <utils/compiler.h>


/* A64 instructions are always 32 bits. */
#define BL_INSN_SIZE 4


#define INST_SYSCALL    0x01, 0x00, 0x00, 0xd4  /*0xd4000001 svc #0  = syscall*/
#define INST_INT3       0xa0, 0x00, 0x20, 0xd4  /*0xd42000a0 brk #5  = int3*/
#define INST_CALLQ      modify_me               /* callq */
#define INST_JMPQ       modify_me               /* jmpq */

#define JMP_TABLE_JUMP_AARCH64  0xd61f022058000051 /*  ldr x17 #8; br x17 */
#define JMP_TABLE_JUMP_ARCH     JMP_TABLE_JUMP_AARCH64

// see linux/scripts/recordmcount.c
static unsigned char __unused ideal_nop4_arm_le[4] = { 0x00, 0x00, 0xa0, 0xe1 }; /* mov r0, r0 */
static unsigned char __unused ideal_nop4_arm_be[4] = { 0xe1, 0xa0, 0x00, 0x00 }; /* mov r0, r0 */
static unsigned char __unused ideal_nop4_arm64[4] = {0x1f, 0x20, 0x03, 0xd5};

