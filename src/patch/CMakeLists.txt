# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
include_directories(..)

add_subdirectory(objects)

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
