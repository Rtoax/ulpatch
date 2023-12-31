# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com>
#
include_directories(..)

add_subdirectory(objects)

find_library(ELF elf /usr/lib64)

link_libraries(${ELF}
	ulpatch_utils
	ulpatch_utils_arch
	ulpatch_elf
)

add_definitions(-MD -Wall -Werror -D_GNU_SOURCE -Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

add_library(ulpatch_patch STATIC ${LIB_SOURCES})

target_compile_definitions(ulpatch_patch PRIVATE ${UTILS_FLAGS})

