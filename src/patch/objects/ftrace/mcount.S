// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#if defined(__x86_64__)
#include "utils/arch/x86_64/mcount.S"
#elif defined(__aarch64__)
#include "utils/arch/aarch64/mcount.S"
#endif
