# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#

set(make_include ${PROJECT_SOURCE_DIR}/src/)
message(STATUS "=== Compile ftrace object ${make_include}")
execute_process(
	COMMAND make INCS1="-I${make_include}"
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/patch/objects/ftrace
	TIMEOUT 3
)

