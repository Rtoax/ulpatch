# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2026 Rong Tao
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

add_library(ulpatch_init STATIC
	init.c
	version.c
)

target_compile_definitions(ulpatch_init PRIVATE ${UTILS_CFLAGS_MACROS})
target_link_libraries(ulpatch_init PRIVATE
	${ELF} ${BFD} ${CAPSTONE} ${LIBSSL} ${LIBCRYPTO} ${LIBUNWIND} ${LIBUNWIND_ARCH} ulpatch_elf
)

link_libraries(${ELF} ${RT}
	ulpatch_elf
	ulpatch_init
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
add_custom_target(ulpconfig ALL DEPENDS ${PROJECT_SOURCE_DIR}/src/ulpconfig.sh.in)
add_custom_command(
	TARGET ulpconfig
	BYPRODUCTS ulpconfig
	COMMAND cp ${PROJECT_SOURCE_DIR}/src/ulpconfig.sh.in ${CMAKE_CURRENT_BINARY_DIR}/ulpconfig
	COMMAND sed -i 's|@ULP_CONFIG_VERSION@|${ULPATCH_VERSION}|g' ${CMAKE_CURRENT_BINARY_DIR}/ulpconfig
	COMMAND sed -i 's|@ULPATCH_VERSION_MAJOR@|${ULPATCH_VERSION_MAJOR}|g' ${CMAKE_CURRENT_BINARY_DIR}/ulpconfig
	COMMAND sed -i 's|@ULPATCH_VERSION_MINOR@|${ULPATCH_VERSION_MINOR}|g' ${CMAKE_CURRENT_BINARY_DIR}/ulpconfig
	COMMAND sed -i 's|@ULPATCH_VERSION_PATCH@|${ULPATCH_VERSION_PATCH}|g' ${CMAKE_CURRENT_BINARY_DIR}/ulpconfig
	PRE_BUILD
	COMMENT "Build ulpconfig"
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/
)

if(CONFIG_BUILD_TESTING)
	add_subdirectory(tests)
endif()
