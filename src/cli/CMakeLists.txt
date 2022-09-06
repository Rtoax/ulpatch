# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

PROJECT(libupatch_cli)

include_directories(..)

find_library(PTHREAD pthread /usr/lib64)
if(HAVE_LINENOISE)
	find_library(LINENOISE linenoise /usr/lib64)
endif()

link_libraries(${ELF} ${PTHREAD} ${LINENOISE} upatch_utils upatch_elf)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

add_library(upatch_cli STATIC ${LIB_SOURCES})

target_compile_definitions(upatch_cli PRIVATE ${UTILS_FLAGS})

