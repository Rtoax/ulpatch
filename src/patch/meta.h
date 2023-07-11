// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 CESTC, Co. Rong Tao <rongtao@cestc.cn> */
#pragma once

#ifndef __ELF_UPATCH_H
#error "Don not install meta.h directly, install patch.h instead."
#endif

#include <stdint.h>

/* This header use to Identifier Patch metadata info in target process. If that,
 * the task user address space will mmap serial of pages into target address
 * space. */

#define SEC_UPATCH_MAGIC	".UPATCH"
#define SEC_UPATCH_STRTAB	".upatch.strtab"
#define SEC_UPATCH_STRTAB_LABEL	"upatch_strtab"
#define SEC_UPATCH_INFO	".upatch.info"

/* patch_type */
enum patch_type {
	UPATCH_TYPE_UNKNOWN,
	UPATCH_TYPE_PATCH,
	UPATCH_TYPE_FTRACE,
};
#define UPATCH_TYPE_FTRACE_STR	"uftrace"
#define UPATCH_TYPE_PATCH_STR	"upatch"

/**
 * Every patch has this information, it's metadata for each patch.
 *
 * @patch_type: the Patch type, see UPATCH_TYPE_PATCH, etc.
 * @src_func: the source function in Patch
 * @dst_func: the destination function in target task
 * @author: who wrote this patch code
 */
#define UPATCH_INFO(patch_type, src_func, dst_func, author) \
__asm__ (	\
	"	.pushsection " SEC_UPATCH_STRTAB ", \"a\", @progbits\n"	\
	SEC_UPATCH_STRTAB_LABEL ": \n"	\
	"	.string \"" SEC_UPATCH_MAGIC "\" \n"	\
	"	.string \"" #patch_type "\" \n"	\
	"	.string \"" #src_func "\" \n"	\
	"	.string \"" #dst_func "\" \n"	\
	"	.string \"" author "\" \n"	\
	"	.popsection \n"	\
	"	.pushsection " SEC_UPATCH_INFO ", \"aw\", @progbits\n"	\
	"	.quad 0\n" /* target function address */	\
	"	.quad 0\n" /* patch function address */	\
	"	.quad 0\n" /* virtual address to modify in target process */	\
	"	.quad 0\n" /* original value */	\
	"	.long 0 \n"	\
	"	.byte 1, 2, 3, 4 \n"	\
	"	.popsection \n"	\
);

/**
 * each element point each string in SEC_UPATCH_STRTAB
 *
 * @patch_type patch type, see UPATCH_TYPE_PATCH, etc.
 * @src_func source function
 * @dst_func destination function
 * @author Author of this patch
 */
struct upatch_strtab {
	/* Must be SEC_UPATCH_MAGIC */
	const char *magic;
	const char *patch_type;
	const char *src_func;
	const char *dst_func;
	const char *author;
};

/**
 * Point to SEC_UPATCH_INFO section
 *
 * Example:
 *
 * 0000000000405fe0 <hello>:
 *  405fe0:	55                   	push   %rbp
 *  405fe1:	48 89 e5             	mov    %rsp,%rbp
 *  405fe4:	41 57                	push   %r15
 *  ...
 * 0000000000408060 <new_hello>:
 *  408060:	55                   	push   %rbp
 *  408061:	48 89 e5             	mov    %rsp,%rbp
 *  408064:	41 57                	push   %r15
 *
 * After patching:
 * 0000000000405fe0 <hello>:
 *  405fe0:	75 xx xx xx xx          jmp    new_hello
 *  ...
 * 0000000000408060 <new_hello>:
 *  408060:	55                   	push   %rbp
 *  408061:	48 89 e5             	mov    %rsp,%rbp
 *  408064:	41 57                	push   %r15
 *
 * Then:
 * target_func_addr = 0x405fe0
 * patch_func_addr  = 0x408060
 * virtual_addr     = 0x405fe1
 * orig_value       = 0x55 48 89 e5 41 ...
 */
struct upatch_info {
	unsigned long target_func_addr;
	unsigned long patch_func_addr;

	unsigned long virtual_addr;
	unsigned long orig_value;

	uint32_t flags;
	char pad[4];
};

