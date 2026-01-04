// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#pragma once

#ifndef __ULP_DEV
# error "Must define __ULP_DEV, maybe use 'ulpconfig --cflags'."
#endif

/**
 * This header use to Identifier Patch metadata info in target process. If that,
 * the task user address space will mmap serial of pages into target address
 * space.
 *
 * No other header files can be included in this source file, this is pure C
 * code.
 */

/**
 * Use to check ulp file is support version or not. If any changes occur to the
 * metadata structure, we should increase this version number.
 */
#define ULPATCH_FILE_VERSION	5

#define SEC_ULPATCH_MAGIC	".ULPATCH"
#define SEC_ULPATCH_STRTAB	".ulpatch.strtab"
#define SEC_ULPATCH_INFO	".ulpatch.info"
#define SEC_ULPATCH_AUTHOR	".ulpatch.author"
#define SEC_ULPATCH_LICENSE	".ulpatch.license"

#ifndef __stringify
#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)
#endif

/**
 * Every patch has this information, it's metadata for each patch.
 *
 * @src_func: the source function in Patch
 * @dst_func: the destination function in target task
 */
#define ULPATCH_INFO(src_func, dst_func)				\
__asm__ (								\
	".pushsection " SEC_ULPATCH_STRTAB ", \"a\", @progbits\n"	\
	"	.string \"" SEC_ULPATCH_MAGIC "\" \n"			\
	"	.string \"" #src_func "\" \n"				\
	"	.string \"" #dst_func "\" \n"				\
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
	"	.long " __stringify(ULPATCH_FILE_VERSION) " \n"		\
	"	.byte 0x11, 0x22, 0x33, 0x44 \n"			\
	".popsection \n"						\
);

/**
 * @author: who wrote this patch code, string
 */
#define ULPATCH_AUTHOR(author)						\
__asm__ (								\
	".pushsection " SEC_ULPATCH_AUTHOR ", \"a\", @progbits\n"	\
	"	.string \"" author "\" \n"				\
	".popsection \n"						\
);

/**
 * @license: what license of this patch, string
 */
#define ULPATCH_LICENSE(license)					\
__asm__ (								\
	".pushsection " SEC_ULPATCH_LICENSE ", \"a\", @progbits\n"	\
	"	.string \"" license "\" \n"				\
	".popsection \n"						\
);

/**
 * each element point each string in SEC_ULPATCH_STRTAB
 *
 * @src_func source function
 * @dst_func destination function
 */
struct ulpatch_strtab {
	/* Must be SEC_ULPATCH_MAGIC */
	const char *magic;
	const char *src_func;
	const char *dst_func;
};

/**
 * SEC_ULPATCH_AUTHOR
 */
struct ulpatch_author {
	const char *author;
};

/**
 * SEC_ULPATCH_LICENSE
 */
struct ulpatch_license {
	const char *license;
};

/**
 * SEC_ULPATCH_INFO section
 */
struct ulpatch_info {
#define ULP_ID_NONE	0
	unsigned int ulp_id;

	unsigned long target_func_addr;
	unsigned long patch_func_addr;

	unsigned long virtual_addr;
	/* store origin data in target process */
	unsigned long orig_code[2];

	/* Record the live patch was patched time */
	unsigned long time;

	unsigned int flags;

	/* Must be ULPATCH_FILE_VERSION */
	unsigned int version;

	char pad[4];
} __attribute__((packed));
