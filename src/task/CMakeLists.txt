# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2025 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

message(STATUS "UTILS Architecture: ${ARCHITECTURE}")

if(BINUTILS_BFD_LIBRARIES)
	find_library(BFD bfd HINTS ${SEARCH_PATH})
endif()

set(disasm)
set(CAPSTONE)

if(CONFIG_CAPSTONE)
	message(STATUS "UTILS Support capstone")
	if(CAPSTONE_LIBRARIES)
		find_library(CAPSTONE capstone HINTS ${SEARCH_PATH})
	endif()
	set(disasm disasm.c)
endif()

add_library(ulpatch_task STATIC
	auxv.c
	core.c
	current.c
	fd.c
	memcpy.c
	patch.c
	proc.c
	symbol.c
	syscall.c
	thread.c
	vma.c
)

target_compile_definitions(ulpatch_task PRIVATE ${UTILS_CFLAGS_MACROS})
target_link_libraries(ulpatch_task PRIVATE
	ulpatch_elf
	ulpatch_utils
)
