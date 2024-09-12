# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})
find_library(PTHREAD pthread HINTS ${SEARCH_PATH})

add_executable(ulpatch_test
	listener.c
	main.c
	test.c
	arch/ftrace.c
	arch/instruments.c
	arch/mcount.c
	elf/core.c
	elf/ehdr.c
	elf/objdump.c
	elf/open.c
	elf/relocs.c
	elf/symbol.c
	patch/asm.c
	patch/meta.c
	patch/object.c
	patch/object/hello/hello.c
	patch/patch.c
	patch/symbol.c
	utils/ansi.c
	utils/backtrace.c
	utils/disasm.c
	utils/file.c
	utils/id.c
	utils/init.c
	utils/list.c
	utils/log.c
	utils/rbtree.c
	utils/string.c
	utils/task.c
	utils/utils.c
	utils/version.c
)

target_include_directories(ulpatch_test PRIVATE ..)

target_compile_definitions(ulpatch_test PRIVATE ${TESTS_CFLAGS_MACROS} ${UTILS_CFLAGS_MACROS})

target_link_libraries(ulpatch_test
	${ELF} ${PTHREAD}
	ulpatch_arch
	ulpatch_elf
	ulpatch_patch
	ulpatch_patch_obj_ftrace
	ulpatch_patch_obj_hello
	ulpatch_utils
)
