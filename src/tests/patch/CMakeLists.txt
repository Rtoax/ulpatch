# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})

add_library(ulpatch_test_patch STATIC
	asm.c
	meta.c
	object.c
	object/hello/hello.c
	patch.c
	symbol.c
)

target_compile_definitions(ulpatch_test_patch PRIVATE ${UTILS_CFLAGS_MACROS})
target_link_libraries(ulpatch_test_patch PRIVATE
	${ELF}
	ulpatch_arch
	ulpatch_utils
)

