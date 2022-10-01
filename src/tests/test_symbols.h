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
/* For example, if you try get 'stdout' address after process start running,
 * the value you get from VMA is not equal to the value you got from target
 * process directly. For 'stdout', you should get it's address from symbol
 * '_IO_2_1_stdout_', the gdb output like:
 *
 * (gdb) p stdout
 * $1 = (FILE *) 0x7ffff7f9d780 <_IO_2_1_stdout_>
 *
 * So, if we found the wrong value with symbol 'stdout', try '_IO_2_1_stdout_'
 * again, maybe we can get what we want.
 */
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

