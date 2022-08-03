# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
# - Try to find CUnit
# Once done this will define
#
#  CUNIT_INCLUDE_DIRS - the CUnit include directory
#  CUNIT_LIBRARIES - Link these to use CUnit
#  CUNIT_DEFINITIONS - Compiler switches required for using CUnit
#  HAVE_CUNIT_BASIC - have CUnit/Basic.h

find_path(CUNIT_INCLUDE_DIRS
  NAMES
    Basic.h
  PATH_SUFFIXES
    CUnit
  PATHS
    ENV CPATH)

find_library(CUNIT_LIBRARIES
  NAMES
    cunit
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibCUnit "Please install the CUnit development package"
	CUNIT_LIBRARIES
	CUNIT_INCLUDE_DIRS)

SET(CMAKE_REQUIRED_LIBRARIES cunit)
INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <CUnit/Basic.h>
int main() {
	return 0;
}" HAVE_CUNIT_BASIC)
SET(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(CUNIT_INCLUDE_DIRS CUNIT_LIBRARIES HAVE_CUNIT_BASIC)
