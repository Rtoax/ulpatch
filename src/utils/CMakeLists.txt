# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com>
#
include_directories(.)
include_directories(..)

add_definitions(-MD -Wall -Werror -D_GNU_SOURCE -Wuninitialized -Wreturn-type)

message(STATUS "=== UTILS Architecture: ${ARCHITECTURE}")
if(LIBUNWIND_LIBRARIES)
	find_library(LIBUNWIND unwind /usr/lib64)
	find_library(LIBUNWIND_ARCH unwind-${ARCHITECTURE} /usr/lib64)
endif()
if(BINUTILS_BFD_LIBRARIES)
	find_library(BFD bfd /usr/lib64)
endif()

link_libraries(${ELF} ${BFD} ${LIBUNWIND} ${LIBUNWIND_ARCH} ulpatch_elf)

add_library(ulpatch_utils STATIC
	ansi.c
	backtrace.c
	callback.c
	file.c
	id.c
	init.c
	list.c
	log.c
	objdump.c
	rbtree.c
	string.c
	task.c
	time.c
	version.c
)

target_compile_definitions(ulpatch_utils PRIVATE ${UTILS_FLAGS})
