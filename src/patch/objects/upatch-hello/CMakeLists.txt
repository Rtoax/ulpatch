# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com>
#
include_directories(../../../)

set(UPATCH_OBJ_TARGET upatch_hello_obj)

find_library(ELF elf /usr/lib64)

link_libraries(${ELF}
	upatch_utils
	upatch_elf
)

add_definitions(-MD -Wall -Werror -O0 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

add_library(${UPATCH_OBJ_TARGET} STATIC ${LIB_SOURCES})

target_compile_definitions(${UPATCH_OBJ_TARGET} PRIVATE
	${UTILS_FLAGS}
	UPATCH_TEST
)

set(UPATCH_HELLO_OBJ upatch-hello.obj)

set(make_include ${PROJECT_SOURCE_DIR}/src/)
message(STATUS "=== Compile upatch hello object ${make_include}")
add_custom_command(
	TARGET ${UPATCH_OBJ_TARGET}
	COMMAND make INCS1="-I${make_include}" FTRACE_OBJ=${UPATCH_HELLO_OBJ}
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/patch/objects/upatch-hello
)

