// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once

int ulpatch_version_major(void);
int ulpatch_version_minor(void);
int ulpatch_version_patch(void);
const char *ulpatch_version(void);
const char *ulpatch_arch(void);
void ulpatch_info(const char *progname);
