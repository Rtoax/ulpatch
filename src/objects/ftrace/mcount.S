// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#if defined(__x86_64__)
# include "arch/x86_64/mcount.S"
#elif defined(__aarch64__)
# include "arch/aarch64/mcount.S"
#else
# error "Not support architecture."
#endif
