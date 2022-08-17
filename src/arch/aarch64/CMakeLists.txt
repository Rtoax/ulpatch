# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
include_directories(.)
include_directories(../..)

message(STATUS "=== Compile for aarch64")

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

add_library(elftools_utils_arch STATIC ${LIB_SOURCES} ${LINENOISE_SRC})

target_compile_definitions(elftools_utils_arch PRIVATE ${UTILS_FLAGS})
