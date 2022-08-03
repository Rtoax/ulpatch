// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#pragma once

#include <stdbool.h>

#include <utils/compiler.h>

#if defined(__x86_64__)
#include <utils/arch/x86_64/instruments.h>
#elif defined(__aarch64__)
#include <utils/arch/aarch64/instruments.h>
#endif

#define SEC_PATCH_PREFIX	".patch"

#define SEC_PATCH_INFO_NAME	SEC_PATCH_PREFIX".info"

#define __PATCH_INFO(tag, name, info)	\
	static const char name[]	\
	__section(SEC_PATCH_INFO_NAME) __attribute__((unused, aligned(1)))	\
	= #tag "=" info

#define PATCH_INFO(tag, info)	__PATCH_INFO(tag, tag, info)


/* there are some macro for patch source code. */
#define PATCH_AUTHOR(_author)	PATCH_INFO(author, _author)

/* ftrace */
#if defined(__x86_64__)
# define MCOUNT_INSN_SIZE	CALL_INSN_SIZE
#elif defined(__aarch64__)
/* A64 instructions are always 32 bits. */
# define MCOUNT_INSN_SIZE	BL_INSN_SIZE
#endif

#define SECTION_FTRACE_TEXT	SEC_PATCH_PREFIX".ftrace.text"
#define SECTION_FTRACE_DATA	SEC_PATCH_PREFIX".ftrace.data"

#define __ftrace_text __section(SECTION_FTRACE_TEXT)
#define __ftrace_data __section(SECTION_FTRACE_DATA)


bool is_ftrace_entry(char *func);

