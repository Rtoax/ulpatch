# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
include_directories(..)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})
find_library(PTHREAD pthread HINTS ${SEARCH_PATH})

link_libraries(${ELF} ${PTHREAD}
	ulpatch_arch
	ulpatch_elf
	ulpatch_patch
	ulpatch_patch_obj_ftrace
	ulpatch_patch_obj_hello
	ulpatch_utils
)

add_definitions(-MD -Wall -Werror -D_GNU_SOURCE -Wuninitialized -Wreturn-type)

aux_source_directory(. DIR_SRCS)
aux_source_directory(arch DIR_ARCH_SRCS)
aux_source_directory(elf DIR_ELF_SRCS)
aux_source_directory(patch DIR_PATCH_SRCS)
aux_source_directory(patch/object/hello/ DIR_PATCH_OBJ_HELLO_SRCS)
aux_source_directory(utils DIR_UTILS_SRCS)

add_executable(ulpatch_test
	${DIR_SRCS}
	${DIR_ARCH_SRCS}
	${DIR_ELF_SRCS}
	${DIR_PATCH_SRCS}
	${DIR_PATCH_OBJ_HELLO_SRCS}
	${DIR_UTILS_SRCS}
)

target_compile_definitions(ulpatch_test PRIVATE ${TESTS_CFLAGS_MACROS} ${UTILS_CFLAGS_MACROS})
