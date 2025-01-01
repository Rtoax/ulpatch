// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once

#include <stdint.h>
#include <utils/compiler.h>
#include <utils/log.h>


#define INT3_INSN_SIZE		1
#define RET_INSN_SIZE		1
#define CALL_INSN_SIZE		5
#define JMP_INSN_SIZE		6 /* indirect jump */
#define JCC8_INSN_SIZE		2
#define JMP8_INSN_SIZE		2
#define JMP32_INSN_SIZE		5
#define MOV_INSN_SIZE		10 /* move 8-byte immediate to reg */
#define ENDBR_INSN_SIZE		4
#define CET_JMP_INSN_SIZE	7 /* indirect jump + prefix */
#define NOP_INSN_SIZE		1

/*
 * Currently, the max observed size in the kernel code is
 * JUMP_LABEL_NOP_SIZE/RELATIVEJUMP_SIZE, which are 5.
 * Raise it if needed.
 */
#define POKE_MAX_OPCODE_SIZE	5

#define INST_SYSCALL    0x0f, 0x05  /* syscall */

#define INST_INT3       0xcc        /* int3 */
#define INST_RET		0xc3		/* ret */
#define INST_CALLQ      0xe8        /* callq */
#define INST_CALL		INST_CALLQ
#define INST_JMPQ       0xe9        /* jmpq */
#define INST_JMP32		INST_JMPQ
#define INST_JMP8		0xeb		/*  */


#define SYSCALL_INSTR \
		INST_SYSCALL, /* syscall */\
		INST_INT3, /* int3 */


#define JMP_TABLE_JUMP_X86_64   0x90900000000225ff /* jmp [rip+2]; nop; nop */
#define JMP_TABLE_JUMP_ARCH     JMP_TABLE_JUMP_X86_64


int text_opcode_size(uint8_t opcode);

// see linux:arch/x86/include/asm/text-patching.h
union text_poke_insn {
	uint8_t text[POKE_MAX_OPCODE_SIZE];
	struct {
		uint8_t opcode;
		int32_t disp;
	} __packed;
};


void *text_gen_insn(union text_poke_insn *insn, uint8_t opcode,
		const void *addr, const void *dest);

uint32_t x86_64_func_callq_offset(void *func);
const char *ulpatch_jmpq_replace(union text_poke_insn *insn, unsigned long ip,
			unsigned long addr);

