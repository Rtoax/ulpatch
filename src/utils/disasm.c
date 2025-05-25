// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024-2025 Rong Tao */
#include <errno.h>
#if defined(CONFIG_CAPSTONE_HEADERS)
# include <capstone/platform.h>
# include <capstone/capstone.h>
#endif

#include "utils/log.h"
#include "utils/string.h"
#include "utils/disasm.h"


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

int fdisasm_arch(FILE *fp, const char *pfx, unsigned long base,
		 unsigned char *code, size_t size)
{
	return fdisasm(fp, pfx, current_disasm_arch(), base, code, size);
}

int fdisasm(FILE *fp, const char *pfx, int disasm_arch, unsigned long base,
	    unsigned char *code, size_t size)
{
	uint64_t address;
	cs_insn *insn;
	size_t j, count;
	csh handle;
	int ret = 0;
	cs_arch arch;
	cs_mode mode;
	int max_bytes_per_insn = 0;
	const char *prefix = pfx ?: "";

	address = base ?: (unsigned long)code;

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

	/* Get max bytes of every insn */
	for (j = 0; j < count; j++)
		if (max_bytes_per_insn < insn[j].size)
			max_bytes_per_insn = insn[j].size;
	/* 1 byte equal to 3 char when print, like 'ff ' */
	max_bytes_per_insn *= 3;

	fprintf(fp, "%sDisasm: code addr %p, size %ld, count %ld\n", prefix,
		code, size, count);

	for (j = 0; j < count; j++) {
		int nbytes = 0;
		fprintf(fp, "%s0x%" PRIx64 ": ", prefix, insn[j].address);
		nbytes = print_bytes(fp, insn[j].bytes, insn[j].size);
		fprintf(fp, "%-*s ", max_bytes_per_insn - nbytes, "");
		fprintf(fp, "\t%s\t%s\n",
			insn[j].mnemonic,
			insn[j].op_str);
	}
	fprintf(fp, "%s0x%" PRIx64 ":\n", prefix,
		insn[j - 1].address + insn[j - 1].size);

	cs_free(insn, count);
close:
	cs_close(&handle);
	return ret;
}

const char *capstone_buildtime_version(void)
{
	static bool init = false;
	static char buf[64];
	if (!init) {
		snprintf(buf, sizeof(buf), "%d.%d.%d", CS_VERSION_MAJOR,
			CS_VERSION_MINOR, CS_VERSION_EXTRA);
		init = true;
	}
	return buf;
}

const char *capstone_runtime_version(void)
{
	static bool init = false;
	static char buf[64];
	if (!init) {
		int major, minor;
		cs_version(&major, &minor);
		snprintf(buf, sizeof(buf), "%d.%d", major, minor);
		init = true;
	}
	return buf;
}
