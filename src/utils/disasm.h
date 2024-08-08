// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao <rtoax@foxmail.com> */

#if defined(CONFIG_CAPSTONE)
# if defined(HAVE_CAPSTONE_CAPSTONE_H)
#  include <capstone/platform.h>
#  include <capstone/capstone.h>
# endif
#else
/* Define some macros to override some APIs */
#endif


