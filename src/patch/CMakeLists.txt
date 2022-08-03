# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
include_directories(..)

find_library(ELF elf /usr/lib64)
find_library(PTHREAD pthread /usr/lib64)

set(JSON_C)
if(JSON_C_LIBRARIES)
find_library(JSON_C json-c /usr/lib64)
endif()

link_libraries(${ELF} ${PTHREAD} ${JSON_C}
	elftools_utils
	elftools_elf
)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

add_library(elftools_patch STATIC ${LIB_SOURCES})

target_compile_definitions(elftools_patch PRIVATE ${UTILS_FLAGS})

