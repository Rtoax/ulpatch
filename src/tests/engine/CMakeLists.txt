# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

add_library(ulpatch_test_engine STATIC
  listener.c
  notify.c
  test.c
)

target_compile_definitions(ulpatch_test_engine PRIVATE ${UTILS_CFLAGS_MACROS})
target_link_libraries(ulpatch_test_engine PRIVATE
  ulpatch_utils
)
