# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
# - Try to find binutils
# Once done this will define
#
#  BINUTILS_FOUND - system has binutils
#  BINUTILS_INCLUDE_DIRS - the binutils include directory
#  BINUTILS_BFD_H - the binutils has bfd.h header
#  BINUTILS_HAVE_BFD_ELF_BFD_FROM_REMOTE_MEMORY - support bfd_elf_bfd_from_remote_memory()

find_path(BINUTILS_INCLUDE_DIRS
	NAMES bfd.h
	PATHS ENV CPATH)

find_library(BINUTILS_BFD_LIBRARIES
	NAMES bfd
	PATHS
		ENV LIBRARY_PATH
		ENV LD_LIBRARY_PATH)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(binutils-devel "Please install the binutils development package"
	BINUTILS_BFD_LIBRARIES
	BINUTILS_INCLUDE_DIRS)

SET(CMAKE_REQUIRED_LIBRARIES elf bfd)
INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <bfd.h>
int main(void) {
	return 0;
}" BINUTILS_BFD_H)
CHECK_C_SOURCE_COMPILES("
#include <bfd.h>
int main(void) {
	struct bfd *bfd, *templ;
	templ = bfd_openr(\"/bin/ls\", NULL);
	bfd = bfd_elf_bfd_from_remote_memory(templ, 0, 0, NULL, NULL);
	return 0;
}" BINUTILS_HAVE_BFD_ELF_BFD_FROM_REMOTE_MEMORY)
SET(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
	BINUTILS_INCLUDE_DIRS
	BINUTILS_BFD_LIBRARIES
	BINUTILS_BFD_H
	BINUTILS_HAVE_BFD_ELF_BFD_FROM_REMOTE_MEMORY
)

