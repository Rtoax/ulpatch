// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include "util.h"

const char *upatch_arch(void)
{
#if defined(__x86_64__)
	return "x86_64";
#elif defined(__aarch64__)
	return "aarch64";
#else
	return "Unsupport";
#endif
}

const char *upatch_version(void)
{
#if !defined(UPATCH_VERSION)
# error "Must define string UPATCH_VERSION"
#endif
	return UPATCH_VERSION;
}

