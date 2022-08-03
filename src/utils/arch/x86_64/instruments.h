// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#pragma once

#include <utils/compiler.h>


#define CALL_INSN_SIZE 5
#define JMP_INSN_SIZE 6 /* indirect jump */
#define JCC8_INSN_SIZE 2
#define JMP32_INSN_SIZE 5
#define MOV_INSN_SIZE 10 /* move 8-byte immediate to reg */
#define ENDBR_INSN_SIZE 4
#define CET_JMP_INSN_SIZE 7 /* indirect jump + prefix */
#define NOP_INSN_SIZE 1


#define INST_SYSCALL    0x0f, 0x05  /* syscall */
#define INST_INT3       0xcc        /* int3 */
#define INST_CALLQ      0xe8        /* callq */
#define INST_JMPQ       0xe9        /* jmpq */

#define JMP_TABLE_JUMP_X86_64   0x90900000000225ff /* jmp [rip+2]; nop; nop */
#define JMP_TABLE_JUMP_ARCH     JMP_TABLE_JUMP_X86_64

// see linux/scripts/recordmcount.c
static unsigned char __unused ideal_nop5_x86_64[5] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
static unsigned char __unused ideal_nop5_x86_32[5] = { 0x3e, 0x8d, 0x74, 0x26, 0x00 };

