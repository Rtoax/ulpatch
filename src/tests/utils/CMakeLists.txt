# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024-2026 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})

set(md5)

if(CONFIG_OPENSSL)
  set(md5 md5.c)
endif()

add_library(ulpatch_test_utils STATIC
  ansi.c
  backtrace.c
  disasm.c
  file.c
  id.c
  list.c
  log.c
  ${md5}
  rbtree.c
  string.c
  utils.c
)

target_compile_definitions(ulpatch_test_utils PRIVATE ${UTILS_CFLAGS_MACROS})
target_link_libraries(ulpatch_test_utils PRIVATE
  ${ELF}
  ulpatch_utils
)

