# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2023 CESTC, Co. Rong Tao <rongtao@cestc.cn>
#
# - Try to find binutils
# Once done this will define
#
#  BINUTILS_FOUND - system has binutils
#  BINUTILS_INCLUDE_DIRS - the binutils include directory
#  BINUTILS_BFD_H - the binutils has version.h header

find_path(BINUTILS_INCLUDE_DIRS
  NAMES
    bfd.h
  PATHS
    ENV CPATH)

find_library(BINUTILS_BFD_LIBRARIES
  NAMES
    bfd
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(binutils-devel "Please install the binutils-devel development package"
  BINUTILS_BFD_LIBRARIES
  BINUTILS_INCLUDE_DIRS)

SET(CMAKE_REQUIRED_LIBRARIES elf)
INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <bfd.h>
int main() {
	return 0;
}" BINUTILS_BFD_H)
SET(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
	BINUTILS_INCLUDE_DIRS
	BINUTILS_BFD_LIBRARIES
	BINUTILS_BFD_H
)

