# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024-2026 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

add_library(ulpatch_test_ftrace STATIC
	ftrace.c
)

target_compile_definitions(ulpatch_test_ftrace PRIVATE ${UTILS_CFLAGS_MACROS})
# '-pg' only add to ftrace tests, because other commands and tests no need to
# mcount@plt call. Such as commit 8a04db16b3b3 ("tests: Add Patch.direct_jmp_far")
# try copy function text to new mmapped memory, however, due to call mcount()
# segfault happend.
target_compile_options(ulpatch_test_ftrace PRIVATE -pg)
target_link_libraries(ulpatch_test_ftrace PRIVATE
	ulpatch_utils
)

