// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#pragma once
#include <errno.h>

#include <utils/compiler.h>

#define DISASM_ARCH_X86_64	1
#define DISASM_ARCH_AARCH64	2

int current_disasm_arch(void);

#if defined(CONFIG_CAPSTONE)
int fdisasm_arch(FILE *fp, unsigned long base, unsigned char *code, size_t size);
int fdisasm(FILE *fp, int disasm_arch, unsigned long base, unsigned char *code,
	    size_t size);
#else
static int __unused fdisasm_arch(FILE *fp, unsigned long base,
				 unsigned char *code, size_t size)
{
	memshow(fp, code, size);
	errno = ENOTSUPP;
	return -ENOTSUPP;
}
static int __unused fdisasm(FILE *fp, int disasm_arch, unsigned long base,
			    unsigned char *code, size_t size)
{
	memshow(fp, code, size);
	errno = ENOTSUPP;
	return -ENOTSUPP;
}
#endif

