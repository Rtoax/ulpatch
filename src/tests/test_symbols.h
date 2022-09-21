// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */

#ifdef TEST_SYM_FOR_EACH
# ifndef TEST_SYM_FOR_EACH_I
#  error "Need define TEST_SYM_FOR_EACH_I"
# endif
for (TEST_SYM_FOR_EACH_I = 0;
	 TEST_SYM_FOR_EACH_I < ARRAY_SIZE(test_symbols);
	 TEST_SYM_FOR_EACH_I++) {
#endif

/* Here start to define symbols
 */
TEST_SYM_NON_STATIC(stdout) // not constant
TEST_SYM(exit)
TEST_SYM(printf)
// errno is macro: (*__errno_location ()), do not test it
// TEST_SYM_NON_STATIC(errno) // (*__errno_location ()): addr 0x0 (0x0)

#if defined(__x86_64__)
TEST_SYM(mcount)
#elif defined(__aarch64__)
TEST_SYM(_mcount)
#endif

TEST_SYM(main)

#ifdef TEST_SYM_FOR_EACH
}
# undef TEST_SYM_FOR_EACH_I
#endif

