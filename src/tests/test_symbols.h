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

/* Here start to define symbols */
/* not constant */
TEST_SYM_NON_STATIC(stdin)
TEST_SYM_NON_STATIC(stdout)
TEST_SYM_NON_STATIC(stderr)

TEST_DYNSYM(exit)
TEST_DYNSYM(printf)

#if defined(__x86_64__)
TEST_DYNSYM(mcount)
#elif defined(__aarch64__)
TEST_DYNSYM(_mcount)
#endif

TEST_SYM_SELF(main)
TEST_SYM_SELF(who_am_i)
TEST_SYM_SELF(test_list)


#ifdef TEST_SYM_FOR_EACH
}
# undef TEST_SYM_FOR_EACH_I
#endif

