# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2025 Rong Tao
#
add_subdirectory(arch)
add_subdirectory(cmds)
add_subdirectory(elf)
add_subdirectory(engine)
add_subdirectory(ftrace)
add_subdirectory(patch)
add_subdirectory(task)
add_subdirectory(ulpatches)
add_subdirectory(utils)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})
find_library(PTHREAD pthread HINTS ${SEARCH_PATH})

if (CONFIG_BUILD_ULFTRACE)
	set(ULFTRACE ${PROJECT_SOURCE_DIR}/src/ulftrace.c)
endif()
if (CONFIG_BUILD_ULTASK)
	set(ULTASK ${PROJECT_SOURCE_DIR}/src/ultask.c)
endif()
add_executable(ulpatch_test
	main.c
	objects.c
	signal.c
	init.c
	version.c
	# When testing ulpatches, the target functions are specified in the
	# patch, and we need to implement these functions in the test program
	# to test them.
	ulpatches-target.c
	${ULFTRACE}
	${PROJECT_SOURCE_DIR}/src/ulpatch.c
	${PROJECT_SOURCE_DIR}/src/ulpinfo.c
	${ULTASK}
)

target_include_directories(ulpatch_test PRIVATE ..)

target_compile_definitions(ulpatch_test PRIVATE ${TESTS_CFLAGS_MACROS} ${UTILS_CFLAGS_MACROS})
target_link_options(ulpatch_test
	PRIVATE
		-Wl,-z,noexecstack
		-Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/metadata.lds
		-Wl,--print-memory-usage
)

target_link_libraries(ulpatch_test PRIVATE
	${ELF} ${PTHREAD}
	ulpatch_arch
	ulpatch_elf
	ulpatch_patch
	ulpatch_utils
)

target_link_libraries(ulpatch_test PRIVATE
	-Wl,--whole-archive
	ulpatch_test_arch
	ulpatch_test_engine
	ulpatch_test_cmds
	ulpatch_test_elf
	ulpatch_test_ftrace
	ulpatch_test_patch
	ulpatch_test_task
	ulpatch_test_utils
	-Wl,--no-whole-archive
)
