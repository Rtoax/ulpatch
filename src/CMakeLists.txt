# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2025 Rong Tao
#
add_subdirectory(arch)
add_subdirectory(elf)
add_subdirectory(objects)
add_subdirectory(patch)
add_subdirectory(task)
add_subdirectory(utils)

include_directories(.)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})
find_library(RT rt HINTS ${SEARCH_PATH})

link_libraries(${ELF} ${RT}
	ulpatch_elf
	ulpatch_patch
	ulpatch_task
	ulpatch_utils
)

# Target: ultask
if (CONFIG_BUILD_ULTASK)
	add_executable(ultask ultask.c)
	target_compile_definitions(ultask PRIVATE ${UTILS_CFLAGS_MACROS} ULP_CMD_MAIN)
endif()

# Target: ulftrace
if (CONFIG_BUILD_ULFTRACE)
	add_executable(ulftrace ulftrace.c)
	target_compile_definitions(ulftrace PRIVATE ${UTILS_CFLAGS_MACROS} ULP_CMD_MAIN)
endif()

# Target: ulpatch
add_executable(ulpatch ulpatch.c)
target_compile_definitions(ulpatch PRIVATE ${UTILS_CFLAGS_MACROS} ULP_CMD_MAIN)

# Target: ulpinfo
add_executable(ulpinfo ulpinfo.c)
target_compile_definitions(ulpinfo PRIVATE ${UTILS_CFLAGS_MACROS} ULP_CMD_MAIN)

message(STATUS "target ulpconfig")
add_custom_target(ulpconfig ALL DEPENDS ${PROJECT_SOURCE_DIR}/src/ulpconfig)
add_custom_command(
	TARGET ulpconfig
	BYPRODUCTS ulpconfig
	COMMAND sed 's|@ULP_CONFIG_VERSION@|${ULPATCH_VERSION}|g' ${PROJECT_SOURCE_DIR}/src/ulpconfig > ulpconfig
	PRE_BUILD
	COMMENT "Build ulpconfig"
	DEPENDS ${PROJECT_SOURCE_DIR}/src/ulpconfig
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/
)

if(CONFIG_BUILD_TESTING)
	add_subdirectory(tests)
endif()
