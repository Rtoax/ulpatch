# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2023 Rong Tao
#
add_subdirectory(utils)
add_subdirectory(elf)
add_subdirectory(patch)
add_subdirectory(arch)

find_package(PkgConfig REQUIRED)

include_directories(.)

find_library(ELF elf /usr/lib64)
find_library(RT rt /usr/lib64)

link_libraries(${ELF} ${RT}
	upatch_utils
	upatch_utils_arch
	upatch_elf
)
add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type -pg)

# Target: utask
add_executable(utask
	utask.c
)
target_compile_definitions(utask PRIVATE ${UTILS_FLAGS})

# Target: uftrace
add_executable(uftrace
	uftrace.c
)
target_compile_definitions(uftrace PRIVATE ${UTILS_FLAGS})

# Target: upatch
add_executable(upatch
	upatch.c
)
target_compile_definitions(upatch PRIVATE ${UTILS_FLAGS})

if(BUILD_TESTING)
add_subdirectory(tests)
endif()
