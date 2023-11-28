// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <stdio.h>

#include "util.h"
#include "compiler.h"


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

int upatch_version_major(void)
{
#if !defined(UPATCH_VERSION_MAJOR)
# error "Must define string UPATCH_VERSION_MAJOR"
#endif
	return UPATCH_VERSION_MAJOR;
}

int upatch_version_minor(void)
{
#if !defined(UPATCH_VERSION_MINOR)
# error "Must define string UPATCH_VERSION_MINOR"
#endif
	return UPATCH_VERSION_MINOR;
}

int upatch_version_patch(void)
{
#if !defined(UPATCH_VERSION_PATCH)
# error "Must define string UPATCH_VERSION_PATCH"
#endif
	return UPATCH_VERSION_PATCH;
}

const char *upatch_version(void)
{
#if !defined(UPATCH_VERSION)
# error "Must define string UPATCH_VERSION"
#endif
	return UPATCH_VERSION;
}

