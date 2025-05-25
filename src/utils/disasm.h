// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024-2025 Rong Tao */
#pragma once
#include <errno.h>
#include <stdio.h>

#include "utils/macros.h"
#include "utils/compiler.h"

#define DISASM_ARCH_X86_64	1
#define DISASM_ARCH_AARCH64	2

int current_disasm_arch(void);

#if defined(CONFIG_CAPSTONE)
int fdisasm_arch(FILE *fp, const char *pfx, unsigned long base,
		 unsigned char *code, size_t size);
int fdisasm(FILE *fp, const char *pfx, int disasm_arch, unsigned long base,
	    unsigned char *code, size_t size);
const char *capstone_buildtime_version(void);
const char *capstone_runtime_version(void);
#else
static int __unused fdisasm_arch(FILE *fp, const char *pfx, unsigned long base,
				 unsigned char *code, size_t size)
{
	memshow(fp, code, size);
	errno = ENOTSUPP;
	return -ENOTSUPP;
}
static int __unused fdisasm(FILE *fp, const char *pfx, int disasm_arch,
			    unsigned long base, unsigned char *code,
			    size_t size)
{
	memshow(fp, code, size);
	errno = ENOTSUPP;
	return -ENOTSUPP;
}
# define capstone_buildtime_version()	"Not Support Capstone"
# define capstone_runtime_version()	"Not Support Capstone"
#endif

