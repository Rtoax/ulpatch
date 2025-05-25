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

#include "init.h"
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

int ulpatch_version_major(void);
int ulpatch_version_minor(void);
int ulpatch_version_patch(void);
const char *ulpatch_version(void);
const char *ulpatch_arch(void);
void ulpatch_info(const char *progname);

void daemonize(void);
