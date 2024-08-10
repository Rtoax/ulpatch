// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>

#include <utils/util.h>
#include <utils/disasm.h>


int fdisasm(FILE *fp, cs_arch arch, cs_mode mode, unsigned char *code,
	    size_t size)
{
	uint64_t address = 0x1000;
	cs_insn *insn;
	size_t j, count;
	csh handle;
	int ret = 0;


	cs_err err = cs_open(arch, mode, &handle);
	if (err) {
		fprintf(stderr, "cs_open() fatal returned: %u\n", err);
		return -EINVAL;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	count = cs_disasm(handle, code, size, address, 0, &insn);
	if (!count) {
		fprintf(stderr, "ERROR: Failed to disasm given code!\n");
		ret = -EINVAL;
		goto close;
	}

	fprintf(fp, "Disasm:\n");
	for (j = 0; j < count; j++)
		fprintf(fp, "0x%" PRIx64 ":\t%s\t%s\n",
			insn[j].address,
			insn[j].mnemonic,
			insn[j].op_str);
	fprintf(fp, "0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

	cs_free(insn, count);
close:
	cs_close(&handle);
	return ret;
}

