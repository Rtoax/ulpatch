# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})

add_library(ulpatch_test_cmds STATIC
	common.c
	ulftrace.c
	ulpatch.c
	ulpinfo.c
	ultask.c
)

target_compile_definitions(ulpatch_test_cmds PRIVATE ${UTILS_CFLAGS_MACROS})
target_link_libraries(ulpatch_test_cmds PRIVATE
	${ELF}
	ulpatch_utils
)

