// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <errno.h>
#if defined(HAVE_CAPSTONE_CAPSTONE_H)
# include <capstone/platform.h>
# include <capstone/capstone.h>
#endif

#include <utils/log.h>
#include <utils/util.h>
#include <utils/disasm.h>


int current_disasm_arch(void)
{
#if defined(__x86_64__)
	return DISASM_ARCH_X86_64;
#elif defined(__aarch64__)
	return DISASM_ARCH_AARCH64;
#else
# error "Not support architecture"
#endif
}

int fdisasm_arch(FILE *fp, unsigned char *code, size_t size)
{
	return fdisasm(fp, current_disasm_arch(), code, size);
}

int fdisasm(FILE *fp, int disasm_arch, unsigned char *code, size_t size)
{
	uint64_t address;
	cs_insn *insn;
	size_t j, count;
	csh handle;
	int ret = 0;
	cs_arch arch;
	cs_mode mode;


	/* FIXME: Prefix */
	address = 0x0;

	switch (disasm_arch) {
	case DISASM_ARCH_X86_64:
		arch = CS_ARCH_X86;
		mode = CS_MODE_64;
		break;
	case DISASM_ARCH_AARCH64:
		arch = CS_ARCH_ARM64;
		mode = CS_MODE_ARM;
		break;
	default:
		ulp_error("Disasm not support architecture.\n");
		return -EINVAL;
	}

	cs_err err = cs_open(arch, mode, &handle);
	if (err) {
		ulp_error("cs_open() fatal returned: %u\n", err);
		return -EINVAL;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	count = cs_disasm(handle, code, size, address, 0, &insn);
	if (!count) {
		ulp_error("ERROR: Failed to disasm given code!\n");
		ret = -EINVAL;
		goto close;
	}

	fprintf(fp, "Disasm:\n");
	for (j = 0; j < count; j++)
		fprintf(fp, "0x%" PRIx64 ":\t%s\t%s\n",
			insn[j].address,
			insn[j].mnemonic,
			insn[j].op_str);
	fprintf(fp, "0x%" PRIx64 ":\n", insn[j - 1].address + insn[j - 1].size);

	cs_free(insn, count);
close:
	cs_close(&handle);
	return ret;
}

