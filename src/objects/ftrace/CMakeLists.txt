# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2025 Rong Tao
#
set(make_include ${PROJECT_SOURCE_DIR}/src/)
message(STATUS "Compile ftrace object ${make_include}")
add_custom_command(
	OUTPUT make-ftrace.log
	COMMAND make INCLUDES="-I${make_include}" ULP_CONFIG=${PROJECT_SOURCE_DIR}/src/ulpconfig.sh.in
	COMMAND make install DESTDIR=${CMAKE_CURRENT_BINARY_DIR} ULP_CONFIG=${PROJECT_SOURCE_DIR}/src/ulpconfig.sh.in
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/objects/ftrace
)
add_custom_target(object_ftrace ALL DEPENDS make-ftrace.log)
