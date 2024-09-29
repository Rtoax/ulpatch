# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
include_directories(../../../)

set(ULPATCH_OBJ_TARGET ulpatch_patch_obj_hello)
set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})

link_libraries(${ELF}
	ulpatch_utils
	ulpatch_elf
)

aux_source_directory(. LIB_SOURCES)

add_library(${ULPATCH_OBJ_TARGET} STATIC ${LIB_SOURCES})

target_compile_definitions(${ULPATCH_OBJ_TARGET} PRIVATE
	${UTILS_CFLAGS_MACROS}
	ULPATCH_TEST
)

set(make_include ${PROJECT_SOURCE_DIR}/src/)
message(STATUS "Compile ulpatch hello ulp ${make_include}")
add_custom_command(
	TARGET ${ULPATCH_OBJ_TARGET}
	COMMAND make INCS1="-I${make_include}" ULP_HELLO_1=${ULP_HELLO_1} ULP_CONFIG=${PROJECT_SOURCE_DIR}/src/ulp-config
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/patch/objects/hello
)

