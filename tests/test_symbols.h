// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */

TEST_SYM(exit)
#if defined(__x86_64__)
TEST_SYM(mcount)
#elif defined(__aarch64__)
TEST_SYM(_mcount)
#endif

