// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022 Rong Tao */
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


// see linux/scripts/recordmcount.c
static unsigned char __unused ideal_nop5_x86_64[5] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
static unsigned char __unused ideal_nop5_x86_32[5] = { 0x3e, 0x8d, 0x74, 0x26, 0x00 };


static inline int text_opcode_size(uint8_t opcode)
{
	int size;

#define __CASE(insn)	\
	case INST_##insn: size = insn##_INSN_SIZE; break

	switch(opcode) {
	__CASE(INT3);   /* INT3_INSN_OPCODE */
	__CASE(RET);    /* RET_INSN_OPCODE */
	__CASE(CALL);   /* CALL_INSN_OPCODE */
	__CASE(JMP32);  /* JMP32_INSN_OPCODE */
	__CASE(JMP8);   /* JMP8_INSN_OPCODE */
	}

	return size;
}

// see linux:arch/x86/include/asm/text-patching.h
union text_poke_insn {
	uint8_t text[POKE_MAX_OPCODE_SIZE];
	struct {
		uint8_t opcode;
		int32_t disp;
	} __packed;
};


static inline __unused
void *text_gen_insn(union text_poke_insn *insn, uint8_t opcode,
		const void *addr, const void *dest)
{
	int size = text_opcode_size(opcode);

	insn->opcode = opcode;

	if (size > 1) {
		insn->disp = (long)dest - (long)(addr + size);

		if (size == 2) {
			/*
			 * Ensure that for JMP9 the displacement
			 * actually fits the signed byte.
			 */
			if (unlikely((insn->disp >> 31) != (insn->disp >> 7))) {
				lerror("ERROR: JMP8.\n");
			}
		}
	}

	return &insn->text;
}

/* find first callq instrument in the front of function body, it's mcount()
 * address.
 */
static __unused uint32_t x86_64_func_callq_offset(void *func)
{
	uint32_t offset = 0;
	while (1) {
		if (*(uint8_t *)(func + offset) == INST_CALLQ)
			break;
		offset += 1;
	}

	return offset;
}

