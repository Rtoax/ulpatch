# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com>
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})

link_libraries(${ELF}
	ulpatch_utils
)

add_definitions(-MD -Wall -Werror -D_GNU_SOURCE -Wuninitialized -Wreturn-type)

add_library(ulpatch_elf STATIC
	ehdr.c
	note.c
	objdump.c
	open.c
	phdr.c
	relocs.c
	section.c
	symbol.c
)

target_compile_definitions(ulpatch_elf PRIVATE ${UTILS_CFLAGS_MACROS})

