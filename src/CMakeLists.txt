# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com>
#
add_subdirectory(utils)
add_subdirectory(elf)
add_subdirectory(patch)
add_subdirectory(arch)

# No need right now
#find_package(PkgConfig REQUIRED)

include_directories(.)

find_library(ELF elf /usr/lib64)
find_library(RT rt /usr/lib64)

link_libraries(${ELF} ${RT}
	ulpatch_utils
	ulpatch_utils_arch
	ulpatch_elf
)
add_definitions(-MD -Wall -Werror -D_GNU_SOURCE -Wuninitialized -Wreturn-type -pg)

# Target: ultask
if (BUILD_ULTASK)
add_executable(ultask ultask.c)
target_compile_definitions(ultask PRIVATE ${UTILS_FLAGS})
endif()

# Target: ulftrace
if (BUILD_ULFTRACE)
add_executable(ulftrace ulftrace.c)
target_compile_definitions(ulftrace PRIVATE ${UTILS_FLAGS})
endif()

# Target: ulpatch
add_executable(ulpatch ulpatch.c)
target_compile_definitions(ulpatch PRIVATE ${UTILS_FLAGS})

# Target: ulpinfo
add_executable(ulpinfo ulpinfo.c)
target_compile_definitions(ulpinfo PRIVATE ${UTILS_FLAGS})

if(BUILD_TESTING)
add_subdirectory(tests)
endif()
