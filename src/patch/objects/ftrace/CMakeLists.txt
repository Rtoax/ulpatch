# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
include_directories(../../../)

set(FTRACE_OBJ_TARGET ftrace_obj)

add_custom_target(${FTRACE_OBJ_TARGET}
	COMMAND echo "=== Make ${FTRACE_OBJ_TARGET}"
)

set(make_include ${PROJECT_SOURCE_DIR}/src/)
message(STATUS "=== Compile ftrace object ${make_include}")
add_custom_command(
	TARGET ${FTRACE_OBJ_TARGET}
	COMMAND make INCS1="-I${make_include}"
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/patch/objects/ftrace
)

find_library(ELF elf /usr/lib64)
find_library(PTHREAD pthread /usr/lib64)

link_libraries(${ELF} ${PTHREAD} ${JSON_C}
	elftools_utils
	elftools_elf
)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

add_library(elftools_patch_obj STATIC ${LIB_SOURCES})

target_compile_definitions(elftools_patch_obj PRIVATE ${UTILS_FLAGS})

