// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once

#include "utils/bitops.h"

/**
 * When task opening, what do you want to do?
 *
 * FTO: Flag of Task when Open.
 */
#define FTO_NONE	0x0
/**
 * Create '/proc' like directory under ULP_PROC_ROOT_DIR. If you need to map a
 * file into target process address space, the flag is necessary.
 */
#define FTO_PROC	BIT(0)
/**
 * This flag will open target process address space's ELF in memory.
 */
#define FTO_VMA_ELF	BIT(1)
/**
 * This flag open /proc/PID/maps specify ELF file.
 */
#define FTO_VMA_ELF_FILE	(BIT(2) | FTO_VMA_ELF)
/**
 * This flag will load all symbols, at same time.
 */
#define FTO_VMA_ELF_SYMBOLS	(BIT(3) | FTO_VMA_ELF | FTO_VMA_ELF_FILE)
/**
 * Open and load /proc/PID/task/, get all target process's thread id.
 */
#define FTO_THREADS	BIT(4)
/**
 * Open task with read and write permission, otherwise readonly.
 */
#define FTO_RDWR	BIT(5)
/**
 * Open /proc/PID/fd/ directory and for each FD.
 */
#define FTO_FD		BIT(6)
/**
 * Open /proc/PID/auxv.
 */
#define FTO_AUXV	BIT(7)
/**
 * Open /proc/PID/status.
 */
#define FTO_STATUS	BIT(8)

#define FTO_ALL 0xffffffff

#define FTO_ULFTRACE	(FTO_PROC | \
			FTO_VMA_ELF_SYMBOLS | \
			FTO_THREADS | \
			FTO_RDWR | \
			FTO_FD | \
			FTO_AUXV | \
			FTO_STATUS)
#define FTO_ULPATCH	FTO_ULFTRACE
