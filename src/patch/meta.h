// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#pragma once

#ifndef __ULP_DEV
# error "Must define __ULPATCH_DEV, and make sure what do you do."
#endif

/* This header use to Identifier Patch metadata info in target process. If that,
 * the task user address space will mmap serial of pages into target address
 * space.
 *
 * No other header files can be included in this source file, this is pure C
 * code.
 */

#define SEC_ULPATCH_MAGIC	".ULPATCH"
#define SEC_ULPATCH_STRTAB	".ulpatch.strtab"
#define SEC_ULPATCH_INFO	".ulpatch.info"

/**
 * Every patch has this information, it's metadata for each patch.
 *
 * @src_func: the source function in Patch
 * @dst_func: the destination function in target task
 * @author: who wrote this patch code
 */
#define ULPATCH_INFO(src_func, dst_func, author) \
__asm__ (								\
	".pushsection " SEC_ULPATCH_STRTAB ", \"a\", @progbits\n"	\
	"	.string \"" SEC_ULPATCH_MAGIC "\" \n"			\
	"	.string \"" #src_func "\" \n"				\
	"	.string \"" #dst_func "\" \n"				\
	"	.string \"" author "\" \n"				\
	".popsection \n"						\
	".pushsection " SEC_ULPATCH_INFO ", \"aw\", @progbits\n"	\
	"	.long 0\n" /* ulp_id */					\
	"	.quad 0\n" /* target function address */		\
	"	.quad 0\n" /* patch function address */			\
	"	.quad 0\n" /* address to modify in target process */	\
	"	.quad 0\n" /* original value1 */			\
	"	.quad 0\n" /* original value2 */			\
	"	.quad 0\n" /* patched time(2) */			\
	"	.long 0\n" /* flags */					\
	"	.long " ULPATCH_FILE_VERSION " \n"			\
	"	.byte 1, 2, 3, 4 \n"					\
	".popsection \n"						\
);

/**
 * each element point each string in SEC_ULPATCH_STRTAB
 *
 * @src_func source function
 * @dst_func destination function
 * @author Author of this patch
 */
struct ulpatch_strtab {
	/* Must be SEC_ULPATCH_MAGIC */
	const char *magic;
	const char *src_func;
	const char *dst_func;
	const char *author;
};

/**
 * Point to SEC_ULPATCH_INFO section
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
struct ulpatch_info {
#define ULP_ID_NONE	0
	unsigned int ulp_id;

	unsigned long target_func_addr;
	unsigned long patch_func_addr;

	unsigned long virtual_addr;
	/* store origin data in target process */
	unsigned long orig_value[2];

	/* Record the patch time */
	unsigned long time;

	unsigned int flags;

/* Use to check support version or not. */
#define ULPATCH_FILE_VERSION	"2"
	unsigned int version;

	char pad[4];
};

