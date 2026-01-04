// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#pragma once

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 4096
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((unsigned long) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
	((type *)(((char *)(ptr)) - offsetof(type, member)))
#endif

#ifndef MAX
#define MAX(a, b) ((a > b) ? a : b)
#endif

#ifndef MIN
#define MIN(a, b) ((a > b) ? b : a)
#endif

#define ELF_MIN_ALIGN	PAGE_SIZE

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#ifndef ROUND_DOWN
#define ROUND_DOWN(x, m) ((x) & ~((m) - 1))
#endif
#ifndef ROUND_UP
#define ROUND_UP(x, m) (((x) + (m) - 1) & ~((m) - 1))
#endif

#ifndef PAGE_DOWN
#define PAGE_DOWN(x) ROUND_DOWN(x, PAGE_SIZE)
#endif
#ifndef PAGE_UP
#define PAGE_UP(x) ROUND_UP(x, PAGE_SIZE)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#if defined(HAVE_KERNEL_HEADERS_CONST_H)
#include <linux/const.h>
#endif

#if !defined(KERNEL_HEADERS_CONST___ALIGN_KERNEL_H)
#if !defined(__ALIGN_KERNEL)
# define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#endif
#if !defined(__ALIGN_KERNEL_MASK)
# define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#endif

#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

/* see linux:include/linux/kernel.h */
/* @a is a power of 2 value */
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))

#ifndef ENOTSUPP
# define ENOTSUPP	524
#endif

/* see linux:include/linux/sizes.h */
#define SZ_1				0x00000001
#define SZ_2				0x00000002
#define SZ_4				0x00000004
#define SZ_8				0x00000008
#define SZ_16				0x00000010
#define SZ_32				0x00000020
#define SZ_64				0x00000040
#define SZ_128				0x00000080
#define SZ_256				0x00000100
#define SZ_512				0x00000200

#define SZ_1K				0x00000400
#define SZ_2K				0x00000800
#define SZ_4K				0x00001000
#define SZ_8K				0x00002000
#define SZ_16K				0x00004000
#define SZ_32K				0x00008000
#define SZ_64K				0x00010000
#define SZ_128K				0x00020000
#define SZ_256K				0x00040000
#define SZ_512K				0x00080000

#define SZ_1M				0x00100000
#define SZ_2M				0x00200000
#define SZ_4M				0x00400000
#define SZ_8M				0x00800000
#define SZ_16M				0x01000000
#define SZ_32M				0x02000000
#define SZ_64M				0x04000000
#define SZ_128M				0x08000000
#define SZ_256M				0x10000000
#define SZ_512M				0x20000000

#define SZ_1G				0x40000000
#define SZ_2G				0x80000000

#define KB (sizeof(uint8_t) * 1024UL)
#define MB (KB * 1024UL)
#define GB (MB * 1024UL)


/* all output need file store here, mkdir(2) it before running. */
#define ULP_PROC_ROOT_DIR	"/tmp/ulpatch"

#define MODE_0777 (S_IRUSR | S_IWUSR | S_IXUSR | \
		   S_IRGRP | S_IWGRP | S_IXGRP | \
		   S_IROTH | S_IWOTH | S_IXOTH)


/* Indirect stringification.  Doing two levels allows the parameter to be a
 * macro itself.  For example, compile with -DFOO=bar, __stringify(FOO)
 * converts to "bar".
 * see linux:include/linux/stringify.h
 */
#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)
