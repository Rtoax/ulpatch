# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2025 Rong Tao
#
# - Try to find libelf
# Once done this will define
#
#  LIBELF_FOUND - system has libelf
#  LIBELF_INCLUDE_DIRS - the libelf include directory
#  LIBELF_LIBRARIES - Link these to use libelf
#  LIBELF_DEFINITIONS - Compiler switches required for using libelf
#  ELF_GETSHDRSTRNDX - the libelf has elf_getshdrstrndx() api

find_path(LIBELF_INCLUDE_DIRS
	NAMES libelf.h
	PATH_SUFFIXES libelf
	PATHS
		ENV CPATH)

find_library(LIBELF_LIBRARIES
	NAMES elf
	PATH_SUFFIXES libelf
	PATHS
		ENV LIBRARY_PATH
		ENV LD_LIBRARY_PATH)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibElf "Please install the libelf development package"
	LIBELF_LIBRARIES
	LIBELF_INCLUDE_DIRS)

SET(CMAKE_REQUIRED_LIBRARIES elf)
INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <libelf.h>
int main(void) {
	Elf *e = (Elf*)0;
	size_t sz;
	elf_getshdrstrndx(e, &sz);
	return 0;
}" ELF_GETSHDRSTRNDX)
SET(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(LIBELF_INCLUDE_DIRS LIBELF_LIBRARIES ELF_GETSHDRSTRNDX)
