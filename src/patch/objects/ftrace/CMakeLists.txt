# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
include_directories(../../../)

enable_language(C ASM)

set(ASM_OPTIONS "-x assembler-with-cpp")
set(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS} ${ASM_OPTIONS}")

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

add_definitions(-MD -Wall -Werror -O0 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

# Need to explicitly add assembly files
file(GLOB_RECURSE LIB_ASM_SOURCES
	mcount.S
)

add_library(elftools_patch_obj STATIC ${LIB_SOURCES} ${LIB_ASM_SOURCES})

target_compile_definitions(elftools_patch_obj PRIVATE
	${UTILS_FLAGS}
	ELFTOOLS_TEST
)

