# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Rong Tao
#
# - Try to find zstd
# Once done this will define
#
#  LIBZSTD_ZSTD_H - system has zstd.h header
#  LIBZSTD_LIBRARIES - system has zstd library

find_path(LIBZSTD_ZSTD_H
	NAMES zstd.h
	PATHS ENV CPATH)

find_library(LIBZSTD_LIBRARIES
	NAMES zstd
	PATHS
		ENV LIBRARY_PATH
		ENV LD_LIBRARY_PATH)

mark_as_advanced(
	LIBZSTD_ZSTD_H
	LIBZSTD_LIBRARIES
)
