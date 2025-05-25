// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once
#include <sys/types.h>

void ulpatch_init(void);

int ulp_page_size(void);
int ulp_page_shift(void);

bool is_verbose(void);
int get_verbose(void);
void enable_verbose(int verbose);
void reset_verbose(void);
int str2verbose(const char *str);

bool is_dry_run(void);
void enable_dry_run(void);
