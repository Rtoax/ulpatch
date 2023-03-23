# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2023 CESTC, Co. Rong Tao <rongtao@cestc.cn>
#
# - Try to find libunwind
# Once done this will define
#
#  LIBUNWIND_FOUND - system has libunwind
#  LIBUNWIND_INCLUDE_DIRS - the libunwind include directory
#  LIBUNWIND_LIBRARIES - Link these to use libunwind
#  LIBUNWIND_DEFINITIONS - Compiler switches required for using libunwind
#  LIBUNWIND_LIBUNWIND_H - Has libunwind.h

find_path(LIBUNWIND_INCLUDE_DIRS
  NAMES
    libunwind.h
  PATHS
    ENV CPATH)

find_library(LIBUNWIND_LIBRARIES
  NAMES
    unwind
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibElf "Please install the libunwind development package"
  LIBUNWIND_LIBRARIES
  LIBUNWIND_INCLUDE_DIRS)

SET(CMAKE_REQUIRED_LIBRARIES unwind)
INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <libunwind.h>
int main() {
	return 0;
}" LIBUNWIND_LIBUNWIND_H)
SET(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
	LIBUNWIND_INCLUDE_DIRS
	LIBUNWIND_LIBRARIES
	LIBUNWIND_LIBUNWIND_H
)

