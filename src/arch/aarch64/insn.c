// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <errno.h>

#include <utils/util.h>
#include <utils/log.h>
#include <task/task.h>

#include <arch/aarch64/instruments.h>
#include <arch/aarch64/debug-monitors.h>

/*
 * In ARMv8-A, A64 instructions have a fixed length of 32 bits and are always
 * little-endian.
 */
int aarch64_insn_read(struct task_struct *task, unsigned long addr,
		      uint32_t *insnp)
{
	int ret;
	uint32_t val;

	ret = memcpy_from_task(task, &val, addr, AARCH64_INSN_SIZE);
	if (ret)
		*insnp = val;

	return ret?0:-1;
}

int aarch64_insn_write(struct task_struct *task, unsigned long addr,
		       uint32_t insn)
{
	uint32_t *tp = (uint32_t *)addr;
	int ret;

	/* A64 instructions must be word aligned */
	if ((uintptr_t)tp & 0x3)
		return -EINVAL;

	ret = memcpy_to_task(task, addr, &insn, AARCH64_INSN_SIZE);
	if (ret) {
		// TODO
		//__flush_icache_range((uintptr_t)tp,
		//		     (uintptr_t)tp + AARCH64_INSN_SIZE);
	}

	return ret ? 0 : -1;
}

// see arch/arm64/kernel/insn.c same function
static inline long branch_imm_common(unsigned long pc, unsigned long addr,
				     long range)
{
	long offset;

	if ((pc & 0x3) || (addr & 0x3)) {
		ulp_error("A64 instructions must be word aligned.\n");
		return range;
	}

	offset = ((long)addr - (long)pc);

	if (offset < -range || offset >= range) {
		ulp_error("offset out of range.\n");
		return range;
	}

	return offset;
}

static int aarch64_get_imm_shift_mask(enum aarch64_insn_imm_type type,
				      uint32_t *maskp, int *shiftp)
{
	uint32_t mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_26:
		mask = BIT(26) - 1;
		shift = 0;
		break;
	case AARCH64_INSN_IMM_19:
		mask = BIT(19) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_16:
		mask = BIT(16) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_14:
		mask = BIT(14) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_12:
		mask = BIT(12) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_9:
		mask = BIT(9) - 1;
		shift = 12;
		break;
	case AARCH64_INSN_IMM_7:
		mask = BIT(7) - 1;
		shift = 15;
		break;
	case AARCH64_INSN_IMM_6:
	case AARCH64_INSN_IMM_S:
		mask = BIT(6) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_R:
		mask = BIT(6) - 1;
		shift = 16;
		break;
	case AARCH64_INSN_IMM_N:
		mask = 1;
		shift = 22;
		break;
	default:
		return -EINVAL;
	}

	*maskp = mask;
	*shiftp = shift;

	return 0;
}

#define ADR_IMM_HILOSPLIT	2
#define ADR_IMM_SIZE		SZ_2M
#define ADR_IMM_LOMASK		((1 << ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_HIMASK		((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_LOSHIFT		29
#define ADR_IMM_HISHIFT		5

uint64_t aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type,
			uint32_t insn)
{
	uint32_t immlo, immhi, mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_ADR:
		shift = 0;
		immlo = (insn >> ADR_IMM_LOSHIFT) & ADR_IMM_LOMASK;
		immhi = (insn >> ADR_IMM_HISHIFT) & ADR_IMM_HIMASK;
		insn = (immhi << ADR_IMM_HILOSPLIT) | immlo;
		mask = ADR_IMM_SIZE - 1;
		break;
	default:
		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
			ulp_error("aarch64_insn_decode_immediate: unknown immediate encoding %d\n",
			       type);
			return 0;
		}
	}

	return (insn >> shift) & mask;
}

uint32_t aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
				       uint32_t insn, uint64_t imm)
{
	uint32_t immlo, immhi, mask;
	int shift;

	if (insn == AARCH64_BREAK_FAULT)
		return AARCH64_BREAK_FAULT;

	switch (type) {
	case AARCH64_INSN_IMM_ADR:
		shift = 0;
		immlo = (imm & ADR_IMM_LOMASK) << ADR_IMM_LOSHIFT;
		imm >>= ADR_IMM_HILOSPLIT;
		immhi = (imm & ADR_IMM_HIMASK) << ADR_IMM_HISHIFT;
		imm = immlo | immhi;
		mask = ((ADR_IMM_LOMASK << ADR_IMM_LOSHIFT) |
			(ADR_IMM_HIMASK << ADR_IMM_HISHIFT));
		break;
	default:
		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
			ulp_error("aarch64_insn_encode_immediate: unknown immediate encoding %d\n",
			       type);
			return AARCH64_BREAK_FAULT;
		}
	}

	/* Update the immediate field. */
	insn &= ~(mask << shift);
	insn |= (imm & mask) << shift;

	return insn;
}

uint32_t aarch64_insn_gen_branch_imm(unsigned pc, unsigned long addr,
				     enum aarch64_insn_branch_type type)
{
	uint32_t insn;
	long offset;

	/* B/BL support [-128, 128M) offset
	 * ARM64 virtual address arrangement guarantees all kernel and module texts
	 * are within +/-128M, so does userspace applications.
	 */
	offset = branch_imm_common(pc, addr, SZ_128M);
	if (offset >= SZ_128M)
		return AARCH64_BREAK_FAULT;

	switch (type) {
	case AARCH64_INSN_BRANCH_LINK:
		insn = aarch64_insn_get_bl_value();
		break;
	case AARCH64_INSN_BRANCH_NOLINK:
		insn = aarch64_insn_get_b_value();
		break;
	default:
		ulp_error("unknown branch encoding %d\n", type);
		return AARCH64_BREAK_FAULT;
	}

	return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_26, insn,
					     offset >> 2);
}

uint32_t aarch64_func_bl_offset(void *func)
{
	uint32_t offset = 0;
	while (1) {
		if (aarch64_insn_is_bl(*(uint32_t *)(func + offset)))
			break;
		offset += AARCH64_INSN_SIZE;
	}

	return offset;
}

