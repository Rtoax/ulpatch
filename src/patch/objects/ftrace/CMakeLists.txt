# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com>
#
include_directories(../../../)

enable_language(C ASM)

set(FTRACE_OBJ_TARGET ulpatch_patch_obj_ftrace)

find_library(ELF elf /usr/lib64)

link_libraries(${ELF}
	ulpatch_utils
	ulpatch_elf
)

add_definitions(-MD -Wall -Werror -D_GNU_SOURCE -Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

# Need to explicitly add assembly files
file(GLOB_RECURSE LIB_ASM_SOURCES
	mcount.S
)

add_library(${FTRACE_OBJ_TARGET} STATIC ${LIB_SOURCES} ${LIB_ASM_SOURCES})

target_compile_definitions(${FTRACE_OBJ_TARGET} PRIVATE
	${UTILS_FLAGS}
	ULPATCH_TEST
)

set(ASM_OPTIONS "-x assembler-with-cpp")
set(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS} ${ASM_OPTIONS}")

set(FTRACE_MCOUNT_OBJ ftrace-mcount.obj)

set(make_include ${PROJECT_SOURCE_DIR}/src/)
message(STATUS "=== Compile ftrace object ${make_include}")
add_custom_command(
	TARGET ${FTRACE_OBJ_TARGET}
	COMMAND make INCS1="-I${make_include}" FTRACE_OBJ=${FTRACE_MCOUNT_OBJ}
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/patch/objects/ftrace
)

