# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com>
#
include_directories(../../../)

set(ULPATCH_OBJ_TARGET ulpatch_patch_obj_hello)
set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})

link_libraries(${ELF}
	ulpatch_utils
	ulpatch_elf
)

add_definitions(-MD -Wall -Werror -D_GNU_SOURCE -Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

add_library(${ULPATCH_OBJ_TARGET} STATIC ${LIB_SOURCES})

target_compile_definitions(${ULPATCH_OBJ_TARGET} PRIVATE
	${UTILS_CFLAGS_MACROS}
	ULPATCH_TEST
)

set(ULPATCH_HELLO_OBJ hello.obj)

set(make_include ${PROJECT_SOURCE_DIR}/src/)
message(STATUS "Compile ulpatch hello object ${make_include}")
add_custom_command(
	TARGET ${ULPATCH_OBJ_TARGET}
	COMMAND make INCS1="-I${make_include}" FTRACE_OBJ=${ULPATCH_HELLO_OBJ}
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/patch/objects/hello
)

