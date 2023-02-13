// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao */
#pragma once

#include <gelf.h>

#include <patch/patch.h>


int apply_relocate_add(const struct load_info *info, GElf_Shdr *sechdrs,
	const char *strtab,	unsigned int symindex, unsigned int relsec);

