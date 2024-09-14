# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

message(STATUS "UTILS Architecture: ${ARCHITECTURE}")

set(unwind)
set(LIBUNWIND)
set(LIBUNWIND_ARCH)

if(LIBUNWIND_LIBUNWIND_H)
	message(STATUS "UTILS Support unwind")
	if(LIBUNWIND_LIBRARIES)
		find_library(LIBUNWIND unwind HINTS ${SEARCH_PATH})
		find_library(LIBUNWIND_ARCH unwind-${ARCHITECTURE} HINTS ${SEARCH_PATH})
	endif()
	set(unwind backtrace.c)
endif()

if(BINUTILS_BFD_LIBRARIES)
	find_library(BFD bfd HINTS ${SEARCH_PATH})
endif()

set(disasm)
set(CAPSTONE)

if(BUILD_WITH_CAPSTONE)
	message(STATUS "UTILS Support capstone")
	if(CAPSTONE_LIBRARIES)
		find_library(CAPSTONE capstone HINTS ${SEARCH_PATH})
	endif()
	set(disasm disasm.c)
endif()

add_library(ulpatch_utils STATIC
	ansi.c
	callback.c
	${disasm}
	file.c
	id.c
	init.c
	list.c
	log.c
	rbtree.c
	string.c
	task.c
	task-current.c
	task-proc.c
	task-syscall.c
	time.c
	${unwind}
	version.c
)

target_compile_definitions(ulpatch_utils PRIVATE ${UTILS_CFLAGS_MACROS})
target_link_libraries(ulpatch_utils PRIVATE
	${ELF} ${BFD} ${CAPSTONE} ${LIBUNWIND} ${LIBUNWIND_ARCH} ulpatch_elf
)
