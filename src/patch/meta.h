// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#pragma once

#ifndef __ELF_UPATCH_H
#error "Don not install meta.h directly, install patch.h instead."
#endif

/* This header use to Identifier Patch metadata info in target process. If that,
 * the task user address space will mmap serial of pages into target address
 * space.
 *
 */

#define SEC_UPATCH_STRTAB	".upatch.strtab"
#define SEC_UPATCH_INFO	".upatch.info"


/* Every patch has this information, it's metadata for each patch.
 *
 * @src_func: the source function in Patch
 * @dst_func: the destination function in target task
 * @author: who wrote this patch code
 *
 */
#define UPATCH_INFO(src_func, dst_func, author)	\
__asm__ (	\
	"	.pushsection " SEC_UPATCH_STRTAB ", \"a\", @progbits\n"	\
	"upatch_strtab: \n"	\
	"	.string \"" #src_func "\" \n"	\
	"	.string \"" #dst_func "\" \n"	\
	"	.string \"" author "\" \n"	\
	"	.popsection \n"	\
	"	.pushsection " SEC_UPATCH_INFO ", \"aw\", @progbits\n"	\
	"	.quad 0 \n"	\
	"	.quad 0 \n"	\
	"	.long 0 \n"	\
	"	.long 0 \n"	\
	"	.quad upatch_strtab \n"	\
	"	.quad 0 \n"	\
	"	.long 0 \n"	\
	"	.byte 0, 0, 0, 0 \n"	\
	"	.popsection \n"	\
);

