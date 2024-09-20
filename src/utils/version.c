// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdio.h>
#include <sys/utsname.h>
#include <gnu/libc-version.h>

#define __ULP_DEV 1
#include <patch/meta.h>

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

void ulpatch_info(const char *progname)
{
	struct utsname name;

	uname(&name);

	printf("System\n");
	printf("  OS: %s %s %s\n", name.sysname, name.release, name.version);
	printf("  Arch: %s\n", name.machine);
	printf("  Glibc: %s-%s\n", gnu_get_libc_version(), gnu_get_libc_release());
	printf("Build\n");
	printf("  version: %s\n", ulpatch_version());
	printf("  GNUC: %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
	printf("  ULP version: %d\n", ULPATCH_FILE_VERSION);
}
