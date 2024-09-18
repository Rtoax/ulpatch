# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})

add_library(ulpatch_elf STATIC
	core.c
	ehdr.c
	note.c
	open.c
	phdr.c
	relocs.c
	section.c
	symbol.c
	symbol-bfd.c
)

target_compile_definitions(ulpatch_elf PRIVATE ${UTILS_CFLAGS_MACROS})
target_link_libraries(ulpatch_elf PRIVATE
	${ELF}
	ulpatch_utils
)


