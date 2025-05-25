// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <limits.h>

#include "utils/file.h"
#include "utils/list.h"
#include "utils/backtrace.h"
#include "utils/macros.h"
#include "utils/time.h"
#include "utils/string.h"


struct nr_idx_bool {
	uint32_t nr;
	uint32_t idx;
	uint32_t is;
};

/* Check some thing */
bool is_root(const char *prog);
