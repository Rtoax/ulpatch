# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
add_subdirectory(arch)
add_subdirectory(elf)
add_subdirectory(patch)
add_subdirectory(utils)

include_directories(.)

set(SEARCH_PATH "/usr/lib64:/usr/lib:/lib64:/lib")

find_library(ELF elf HINTS ${SEARCH_PATH})
find_library(RT rt HINTS ${SEARCH_PATH})

link_libraries(${ELF} ${RT}
	ulpatch_elf
	ulpatch_patch
	ulpatch_utils
)
add_definitions(-MD -Wall -Werror -D_GNU_SOURCE -Wuninitialized -Wreturn-type -pg)

# Target: ultask
if (BUILD_ULTASK)
	add_executable(ultask ultask.c)
	target_compile_definitions(ultask PRIVATE ${UTILS_CFLAGS_MACROS})
endif()

# Target: ulftrace
if (BUILD_ULFTRACE)
	add_executable(ulftrace ulftrace.c)
	target_compile_definitions(ulftrace PRIVATE ${UTILS_CFLAGS_MACROS})
endif()

# Target: ulpatch
add_executable(ulpatch ulpatch.c)
target_compile_definitions(ulpatch PRIVATE ${UTILS_CFLAGS_MACROS})

# Target: ulpinfo
add_executable(ulpinfo ulpinfo.c)
target_compile_definitions(ulpinfo PRIVATE ${UTILS_CFLAGS_MACROS})

message(STATUS "target ulp-config")
add_custom_target(ulp-config ALL DEPENDS ${PROJECT_SOURCE_DIR}/src/ulp-config)
add_custom_command(
	TARGET ulp-config
	BYPRODUCTS ulp-config
	COMMAND sed 's|@ULP_CONFIG_VERSION@|${ULPATCH_VERSION}|g' ${PROJECT_SOURCE_DIR}/src/ulp-config > ulp-config
	PRE_BUILD
	COMMENT "Build ulp-config"
	DEPENDS ${PROJECT_SOURCE_DIR}/src/ulp-config
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/
)

if(BUILD_TESTING)
	add_subdirectory(tests)
endif()
