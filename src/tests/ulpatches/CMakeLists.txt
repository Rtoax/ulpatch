# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2025 Rong Tao
#
set(make_include ${PROJECT_SOURCE_DIR}/src/)
message(STATUS "Compile ulpatch hello ulp ${make_include}")
add_custom_command(
	OUTPUT make-ulpatches.log
	COMMAND make INCS1="-I${make_include}" ULP_CONFIG=${PROJECT_SOURCE_DIR}/src/ulpconfig
	COMMAND make install DESTDIR=${CMAKE_CURRENT_BINARY_DIR} ULP_CONFIG=${PROJECT_SOURCE_DIR}/src/ulpconfig
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/tests/ulpatches
)
add_custom_target(tests_ulpatches ALL DEPENDS make-ulpatches.log)
