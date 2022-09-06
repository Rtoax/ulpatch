# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
find_package(PkgConfig REQUIRED)

include_directories(.)

#pkg_search_module(GTK_3_0 REQUIRED gtk+-3.0)

#message(STATUS "=== GTK_3_0_LIBRARIES: ${GTK_3_0_LIBRARIES}")
#message(STATUS "=== GTK_3_0_INCLUDE_DIRS: ${GTK_3_0_INCLUDE_DIRS}")

#include_directories(${GTK_3_0_INCLUDE_DIRS})


link_libraries(${ELF} ${RT} ${PTHREAD}
	upatch_utils
	upatch_elf
	upatch_cli
)
add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type -pg)

aux_source_directory(. LIB_SOURCES)

add_library(upatch_gtk STATIC ${LIB_SOURCES})

target_compile_definitions(upatch_gtk PRIVATE ${UTILS_FLAGS})
