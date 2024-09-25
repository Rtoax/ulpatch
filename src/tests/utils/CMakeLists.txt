# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})

add_library(ulpatch_test_utils STATIC
	ansi.c
	backtrace.c
	disasm.c
	file.c
	id.c
	init.c
	list.c
	log.c
	rbtree.c
	string.c
	task.c
	task-proc.c
	task-symbol.c
	utils.c
	version.c
)

target_compile_definitions(ulpatch_test_utils PRIVATE ${UTILS_CFLAGS_MACROS})
target_link_libraries(ulpatch_test_utils PRIVATE
	${ELF}
	ulpatch_utils
)

