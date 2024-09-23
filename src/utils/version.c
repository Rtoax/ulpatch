// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdio.h>
#include <sys/utsname.h>
#include <gnu/libc-version.h>

#define __ULP_DEV 1
#include <patch/meta.h>

#include <utils/ansi.h>
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
	printf("\n");
	printf("Build\n");
	printf("  version: %s\n", ulpatch_version());
	printf("  build time: %s\n", ULPATCH_COMPILE_TIME);
	printf("  GNUC(GCC): %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
	printf("  Support:");
#if defined(CONFIG_CAPSTONE)
		printf(" capstone");
#endif
#if defined(CONFIG_LIBUNWIND)
		printf(" libunwind");
#endif
#if defined(HAVE_BINUTILS_BFD_H)
		printf(" bfd");
#endif
		printf("\n");
	printf("\n");
	printf("ULPatch\n");
	printf("  ULP patch version: %d\n", ULPATCH_FILE_VERSION);
	printf("\n");
}
