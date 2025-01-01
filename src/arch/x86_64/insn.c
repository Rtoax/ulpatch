// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <errno.h>

#include <utils/util.h>
#include <utils/log.h>
#include <task/task.h>

#include <arch/x86_64/instruments.h>

/* see linux/scripts/recordmcount.c */
static unsigned char __unused ideal_nop5_x86_64[5] =
	{ 0x0f, 0x1f, 0x44, 0x00, 0x00 };
static unsigned char __unused ideal_nop5_x86_32[5] =
	{ 0x3e, 0x8d, 0x74, 0x26, 0x00 };

int text_opcode_size(uint8_t opcode)
{
	int size = 0;

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
				ulp_error("ERROR: JMP8.\n");
			}
		}
	}

	return &insn->text;
}

/**
 * find first callq instrument in the front of function body, it's mcount()
 * address.
 *
 * FIXME: on Debian/Ubuntu, There is no callq(0xe8) for mcount
 */
uint32_t x86_64_func_callq_offset(void *func)
{
	uint32_t offset = 0;
	while (1) {
		if (*(uint8_t *)(func + offset) == INST_CALLQ)
			break;
		offset += 1;
	}

	return offset;
}
