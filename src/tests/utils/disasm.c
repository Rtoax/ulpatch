// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <sys/types.h>
#include <unistd.h>
#include <utils/log.h>
#include <utils/util.h>
#include <utils/disasm.h>
#include <tests/test_api.h>


#if defined(CONFIG_CAPSTONE)
TEST(Disasm, base, 0)
{
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

	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;

	arch = CS_ARCH_X86;
	mode = CS_MODE_64;
	code = (unsigned char *)X86_64_CODE;
	size = sizeof(X86_64_CODE) - 1;
	print_string_hex(stdout, "Code:", code, size);
	fdisasm(stdout, arch, mode, code, size);

	arch = CS_ARCH_ARM64;
	mode = CS_MODE_ARM;
	code = (unsigned char *)AArch64_CODE;
	size = sizeof(AArch64_CODE) - 1;
	print_string_hex(stdout, "Code:", code, size);
	fdisasm(stdout, arch, mode, code, size);

	return 0;
}
#endif
