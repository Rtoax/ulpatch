// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <sys/types.h>
#include <unistd.h>
#include "utils/log.h"
#include "utils/util.h"
#include "utils/disasm.h"
#include "tests/test-api.h"


#define X86_64_CODE \
	"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\xea\xbe\xad\xde\xff\x25\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff"

#define AArch64_CODE \
	"\x09\x00\x38\xd5" \
	"\xbf\x40\x00\xd5" \
	"\x0c\x05\x13\xd5" \
	"\x20\x50\x02\x0e" \
	"\x20\xe4\x3d\x0f" \
	"\x00\x18\xa0\x5f" \
	"\xa2\x00\xae\x9e" \
	"\x9f\x37\x03\xd5" \
	"\xbf\x33\x03\xd5" \
	"\xdf\x3f\x03\xd5" \
	"\x21\x7c\x02\x9b" \
	"\x21\x7c\x00\x53" \
	"\x00\x40\x21\x4b" \
	"\xe1\x0b\x40\xb9" \
	"\x20\x04\x81\xda" \
	"\x20\x08\x02\x8b" \
	"\x10\x5b\xe8\x3c" \
	"\xfd\x7b\xba\xa9" \
	"\xfd\xc7\x43\xf8"

static int test_disasm_stub1(void)
{
	char buf[] = {"Hello, Rong Tao!"};
	printf("%s\n", buf);
	return 0;
}

static int test_disasm_stub2(void)
{
	return 0;
}

static int test_disasm(int arch, unsigned char *code, size_t size)
{
	print_string_hex(stdout, "Code:", code, size);
	return fdisasm(stdout, "PFX: ", arch, 0, code, size);
}

TEST(Utils_disasm, base, 0)
{
	int ret = 0;
	unsigned char *code;
	size_t size;

	code = (unsigned char *)X86_64_CODE;
	size = sizeof(X86_64_CODE) - 1;
	ret += test_disasm(DISASM_ARCH_X86_64, code, size);

	code = (unsigned char *)AArch64_CODE;
	size = sizeof(AArch64_CODE) - 1;
	ret += test_disasm(DISASM_ARCH_AARCH64, code, size);

	return ret;
}

TEST(Utils_disasm, base_arch, 0)
{
	unsigned char *code = (unsigned char *)test_disasm_stub1;
	size_t size = (test_disasm_stub2 - test_disasm_stub1);

	fprintf(stdout, "Disasm test_disasm_stub2:\n");
	return fdisasm_arch(stdout, "PFX: ", 0, code, size);
}
