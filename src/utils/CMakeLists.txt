# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
include_directories(.)
include_directories(..)

add_subdirectory(arch/)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

if(HAVE_LINENOISE)
	set(LINENOISE_SRC)
else()
	aux_source_directory(linenoise LINENOISE_SRC)
endif()

message(STATUS "=== UTILS Architecture: ${ARCHITECTURE}")
if(LIBUNWIND_LIBRARIES)
	find_library(LIBUNWIND unwind /usr/lib64)
	find_library(LIBUNWIND_ARCH unwind-${ARCHITECTURE} /usr/lib64)
endif()

aux_source_directory(. LIB_SOURCES)

link_libraries(${ELF} ${PTHREAD} ${LIBUNWIND} ${LIBUNWIND_ARCH})

add_library(elftools_utils STATIC ${LIB_SOURCES} ${LINENOISE_SRC})

target_compile_definitions(elftools_utils PRIVATE ${UTILS_FLAGS})
