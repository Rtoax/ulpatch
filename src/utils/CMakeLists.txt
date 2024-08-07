# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com>
#
include_directories(..)

add_definitions(-MD -Wall -Werror -D_GNU_SOURCE -Wuninitialized -Wreturn-type)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

message(STATUS "UTILS Architecture: ${ARCHITECTURE}")
if(LIBUNWIND_LIBRARIES)
	find_library(LIBUNWIND unwind HINTS ${SEARCH_PATH})
	find_library(LIBUNWIND_ARCH unwind-${ARCHITECTURE} HINTS ${SEARCH_PATH})
endif()

if(BINUTILS_BFD_LIBRARIES)
	find_library(BFD bfd HINTS ${SEARCH_PATH})
endif()

if(CAPSTONE_LIBRARIES)
	find_library(CAPSTONE capstone HINTS ${SEARCH_PATH})
endif()

link_libraries(${ELF} ${BFD} ${LIBUNWIND} ${LIBUNWIND_ARCH} ulpatch_elf)

add_library(ulpatch_utils STATIC
	ansi.c
	backtrace.c
	callback.c
	disasm.c
	file.c
	id.c
	init.c
	list.c
	log.c
	rbtree.c
	string.c
	task.c
	time.c
	version.c
)

target_compile_definitions(ulpatch_utils PRIVATE ${UTILS_CFLAGS_MACROS})
