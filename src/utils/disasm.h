// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao <rtoax@foxmail.com> */
#pragma once

#include <utils/compiler.h>

#define DISASM_ARCH_X86_64	1
#define DISASM_ARCH_AARCH64	2

#if defined(CONFIG_CAPSTONE)
int fdisasm(FILE *fp, int disasm_arch, unsigned char *code, size_t size);
#else
static int __unused fdisasm(FILE *fp, int disasm_arch, unsigned char *code,
			    size_t size)
{
	return -ENOSYS;
}
#endif

