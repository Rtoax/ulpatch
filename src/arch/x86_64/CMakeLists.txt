# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com>
#
include_directories(../..)

message(STATUS "=== Compile for x86_64")

add_definitions(-MD -Wall -Werror -D_GNU_SOURCE -Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

add_library(ulpatch_arch STATIC ${LIB_SOURCES})

target_compile_definitions(ulpatch_arch PRIVATE ${UTILS_FLAGS})
