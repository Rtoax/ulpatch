# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024-2025 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})

add_library(ulpatch_test_task STATIC
	core.c
	current.c
	memcpy.c
	proc.c
	symbol.c
	syscall.c
	vma.c
)

target_compile_definitions(ulpatch_test_task PRIVATE ${UTILS_CFLAGS_MACROS})
target_link_libraries(ulpatch_test_task PRIVATE
	${ELF}
	ulpatch_task
)

