# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
# - Try to find elfutils
# Once done this will define
#
#  ELFUTILS_FOUND - system has elfutils
#  ELFUTILS_INCLUDE_DIRS - the elfutils include directory
#  ELFUTILS_VERSION_H - the elfutils has version.h header

find_path(ELFUTILS_INCLUDE_DIRS
  NAMES
    version.h
  PATH_SUFFIXES
    elfutils
  PATHS
    ENV CPATH)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(elfutils-devel "Please install the elfutils-devel development package"
  ELFUTILS_INCLUDE_DIRS)

SET(CMAKE_REQUIRED_LIBRARIES elf)
INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <elfutils/version.h>
int main() {
	return 0;
}" ELFUTILS_VERSION_H)
SET(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(ELFUTILS_INCLUDE_DIRS ELFUTILS_VERSION_H)

