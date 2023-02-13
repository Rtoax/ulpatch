# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2023 Rong Tao
#
include_directories(..)

add_subdirectory(objects)

find_library(ELF elf /usr/lib64)

link_libraries(${ELF}
	upatch_utils
	upatch_utils_arch
	upatch_elf
)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

add_library(upatch_patch STATIC ${LIB_SOURCES})

target_compile_definitions(upatch_patch PRIVATE ${UTILS_FLAGS})

