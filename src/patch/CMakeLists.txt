# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2026 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})

add_library(ulpatch_patch STATIC
	patch.c
)

target_compile_definitions(ulpatch_patch PRIVATE ${UTILS_CFLAGS_MACROS})
target_link_libraries(ulpatch_patch PRIVATE
	${ELF}
	ulpatch_arch
	ulpatch_elf
	ulpatch_utils
)

message(STATUS "target version.h")
add_custom_target(version.h ALL DEPENDS ${PROJECT_SOURCE_DIR}/src/patch/version.h.in)
add_custom_command(
	TARGET version.h
	BYPRODUCTS version.h
	COMMAND cp ${PROJECT_SOURCE_DIR}/src/patch/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/version.h
	COMMAND sed -i 's|@ULP_CONFIG_VERSION@|${ULPATCH_VERSION}|g' ${CMAKE_CURRENT_BINARY_DIR}/version.h
	COMMAND sed -i 's|@ULPATCH_VERSION_MAJOR@|${ULPATCH_VERSION_MAJOR}|g' ${CMAKE_CURRENT_BINARY_DIR}/version.h
	COMMAND sed -i 's|@ULPATCH_VERSION_MINOR@|${ULPATCH_VERSION_MINOR}|g' ${CMAKE_CURRENT_BINARY_DIR}/version.h
	COMMAND sed -i 's|@ULPATCH_VERSION_PATCH@|${ULPATCH_VERSION_PATCH}|g' ${CMAKE_CURRENT_BINARY_DIR}/version.h
	PRE_BUILD
	COMMENT "Build version.h"
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/
)
