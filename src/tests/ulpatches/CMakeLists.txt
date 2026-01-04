# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2026 Rong Tao
#
set(make_include ${PROJECT_SOURCE_DIR}/src/)
message(STATUS "Compile ulpatch hello ulp ${make_include}")
add_custom_command(
	OUTPUT make-ulpatches.log
	DEPENDS
		# Use ulpconfig.sh.in directly
		${PROJECT_SOURCE_DIR}/src/ulpconfig.sh.in
		${CMAKE_CURRENT_SOURCE_DIR}/Makefile
	COMMAND make INCLUDES="-I${make_include}" ULPCONFIG=${PROJECT_SOURCE_DIR}/src/ulpconfig.sh.in
	COMMAND make install DESTDIR=${CMAKE_CURRENT_BINARY_DIR} ULPCONFIG=${PROJECT_SOURCE_DIR}/src/ulpconfig.sh.in
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/tests/ulpatches
)
add_custom_target(tests_ulpatches ALL DEPENDS make-ulpatches.log)
