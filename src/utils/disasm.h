// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao <rtoax@foxmail.com> */
#if defined(CONFIG_CAPSTONE)
# if defined(HAVE_CAPSTONE_CAPSTONE_H)
#  include <capstone/platform.h>
#  include <capstone/capstone.h>

int fdisasm(FILE *fp, cs_arch arch, cs_mode mode, unsigned char *code,
	    size_t size);
# endif
#else
/* Define some macros to override some APIs */
#endif

