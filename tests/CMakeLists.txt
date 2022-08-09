# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
include_directories(../)
include_directories(../src)

find_library(ELF elf /usr/lib64)
find_library(PTHREAD pthread /usr/lib64)

link_libraries(${ELF} ${PTHREAD}
	elftools_elf
	elftools_patch
	elftools_utils
	elftools_utils_arch
	elftools_cli
)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

aux_source_directory(. DIR_SRCS)
aux_source_directory(elf DIR_ELF_SRCS)
aux_source_directory(patch DIR_PATCH_SRCS)
aux_source_directory(cli DIR_CLI_SRCS)
aux_source_directory(utils DIR_UTILS_SRCS)

add_executable(elftools_test
	${DIR_SRCS}
	${DIR_ELF_SRCS}
	${DIR_PATCH_SRCS}
	${DIR_CLI_SRCS}
	${DIR_UTILS_SRCS}
)

target_compile_definitions(elftools_test PRIVATE ${TESTS_FLAGS} ${UTILS_FLAGS})
