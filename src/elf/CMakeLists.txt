# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2023 Rong Tao
#
include_directories(..)

find_library(ELF elf /usr/lib64)

link_libraries(${ELF}
	upatch_utils
	upatch_patch
)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

add_library(upatch_elf STATIC ${LIB_SOURCES})

target_compile_definitions(upatch_elf PRIVATE ${UTILS_FLAGS})

