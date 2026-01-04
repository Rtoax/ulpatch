# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Rong Tao
#
# - Try to find libunwind
# Once done this will define
#
#  OPENSSL_FOUND - system has libunwind
#  OPENSSL_INCLUDE_DIRS - the libunwind include directory
#  OPENSSL_LIBRARIES - Link these to use libunwind
#  OPENSSL_DEFINITIONS - Compiler switches required for using libunwind
#  OPENSSL_OPENSSLV_H - Has libunwind.h

find_path(OPENSSL_INCLUDE_DIRS
	NAMES openssl/opensslv.h
	PATHS ENV CPATH)

find_library(OPENSSL_LIBRARIES
	NAMES ssl
	PATHS
		ENV LIBRARY_PATH
		ENV LD_LIBRARY_PATH)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibSSL "Please install the openssl development package"
	OPENSSL_LIBRARIES
	OPENSSL_INCLUDE_DIRS)

SET(CMAKE_REQUIRED_LIBRARIES unwind)
INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <openssl/opensslv.h>
int main(void) {
	return 0;
}" OPENSSL_OPENSSLV_H)
SET(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
	OPENSSL_INCLUDE_DIRS
	OPENSSL_LIBRARIES
	OPENSSL_OPENSSLV_H
)

