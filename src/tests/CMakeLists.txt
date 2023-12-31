# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com>
#
include_directories(./)
include_directories(../)

find_library(ELF elf /usr/lib64)

link_libraries(${ELF}
	ulpatch_elf
	ulpatch_patch
	ulpatch_patch_obj
	ulpatch_utils
	ulpatch_utils_arch
)

add_definitions(-MD -Wall -Werror -D_GNU_SOURCE -Wuninitialized -Wreturn-type)

aux_source_directory(. DIR_SRCS)
aux_source_directory(elf DIR_ELF_SRCS)
aux_source_directory(patch DIR_PATCH_SRCS)
aux_source_directory(patch/object/ulpatch-hello/ DIR_PATCH_OBJ_HELLO_SRCS)
aux_source_directory(utils DIR_UTILS_SRCS)
aux_source_directory(utils/arch DIR_UTILS_SRCS)

add_executable(ulpatch_test
	${DIR_SRCS}
	${DIR_ELF_SRCS}
	${DIR_PATCH_SRCS}
	${DIR_PATCH_OBJ_HELLO_SRCS}
	${DIR_UTILS_SRCS}
)

target_compile_definitions(ulpatch_test PRIVATE ${TESTS_FLAGS} ${UTILS_FLAGS})
