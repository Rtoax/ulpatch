# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
include_directories(../../../)

set(make_include ${PROJECT_SOURCE_DIR}/src/)
message(STATUS "=== Compile ftrace object ${make_include}")

# this main.out just for add_custom_command()
add_executable(main.out
	main.c
)

add_custom_command(
	#OUTPUT mcount.o
	TARGET main.out
	COMMAND make INCS1="-I${make_include}"
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/patch/objects/ftrace
	BYPRODUCTS mcount.o
)

