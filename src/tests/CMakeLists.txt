# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
add_subdirectory(arch)
add_subdirectory(cmds)
add_subdirectory(elf)
add_subdirectory(ftrace)
add_subdirectory(patch)
add_subdirectory(task)
add_subdirectory(ulpatches)
add_subdirectory(utils)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})
find_library(PTHREAD pthread HINTS ${SEARCH_PATH})

add_executable(ulpatch_test
	listener.c
	notify.c
	objects.c
	test.c
	ulpatch-test.c
	# When testing ulpatches, the target functions are specified in the
	# patch, and we need to implement these functions in the test program
	# to test them.
	ulpatches-target.c
	${PROJECT_SOURCE_DIR}/src/ulftrace.c
	${PROJECT_SOURCE_DIR}/src/ulpatch.c
	${PROJECT_SOURCE_DIR}/src/ulpinfo.c
	${PROJECT_SOURCE_DIR}/src/ultask.c
)

target_include_directories(ulpatch_test PRIVATE ..)

target_compile_definitions(ulpatch_test PRIVATE ${TESTS_CFLAGS_MACROS} ${UTILS_CFLAGS_MACROS})
target_link_options(ulpatch_test PRIVATE -Wl,-z,noexecstack)

target_link_libraries(ulpatch_test PRIVATE
	${ELF} ${PTHREAD}
	ulpatch_arch
	ulpatch_elf
	ulpatch_patch
	ulpatch_utils
	ulpatch_test_arch
	ulpatch_test_cmds
	ulpatch_test_elf
	ulpatch_test_ftrace
	ulpatch_test_patch
	ulpatch_test_task
	ulpatch_test_utils
)
