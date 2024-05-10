// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <stdio.h>

#include <utils/util.h>
#include <utils/compiler.h>


const char *ulpatch_arch(void)
{
#if defined(__x86_64__)
	return "x86_64";
#elif defined(__aarch64__)
	return "aarch64";
#else
	return "Unsupport";
#endif
}

int ulpatch_version_major(void)
{
#if !defined(ULPATCH_VERSION_MAJOR)
# error "Must define string ULPATCH_VERSION_MAJOR"
#endif
	return ULPATCH_VERSION_MAJOR;
}

int ulpatch_version_minor(void)
{
#if !defined(ULPATCH_VERSION_MINOR)
# error "Must define string ULPATCH_VERSION_MINOR"
#endif
	return ULPATCH_VERSION_MINOR;
}

int ulpatch_version_patch(void)
{
#if !defined(ULPATCH_VERSION_PATCH)
# error "Must define string ULPATCH_VERSION_PATCH"
#endif
	return ULPATCH_VERSION_PATCH;
}

const char *ulpatch_version(void)
{
#if !defined(ULPATCH_VERSION)
# error "Must define string ULPATCH_VERSION"
#endif
	return ULPATCH_VERSION;
}

