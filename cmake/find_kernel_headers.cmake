# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
# - Try to find kernel headers
# Once done this will define
#
#  KERNEL_HEADERS_FOUND - system has kernel headers
#  KERNEL_HEADERS_INCLUDE_DIRS - the kernel headers include directory
#  KERNEL_HEADERS_CONST_H - the kernel headers has const.h header
#  KERNEL_HEADERS_CONST___ALIGN_KERNEL_H - the kernel headers const.h has macro __ALIGN_KERNEL
#

find_path(KERNEL_HEADERS_INCLUDE_DIRS
	NAMES version.h
	PATH_SUFFIXES linux
	PATHS ENV CPATH)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(kernel-headers "Please install the kernel-headers development package"
	KERNEL_HEADERS_INCLUDE_DIRS)

SET(CMAKE_REQUIRED_LIBRARIES elf)
INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <linux/const.h>
int main(void) {
	return 0;
}" KERNEL_HEADERS_CONST_H)
CHECK_C_SOURCE_COMPILES("
#include <linux/const.h>
int main(void) {
	long a = __ALIGN_KERNEL(1, 0);
	return 0;
}" KERNEL_HEADERS_CONST___ALIGN_KERNEL_H)
SET(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(KERNEL_HEADERS_INCLUDE_DIRS
	KERNEL_HEADERS_CONST_H
	KERNEL_HEADERS_CONST___ALIGN_KERNEL_H
)

