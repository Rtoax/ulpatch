# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao

CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

PROJECT(elftools)

set(WARNINGS_AS_ERRORS OFF CACHE BOOL "Build with -Werror")
set(BUILD_TESTING ON CACHE BOOL "Build test suite")

# check processor architecture
# only support x86_64 and aarch64 right now.
if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86_64")
message(STATUS "x86_64 architecture detected")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "aarch64")
message(STATUS "aarch64 architecture detected")
else()
message(FATAL_ERROR "host processor architecture is unknown(x86_64,aarch64 only)")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(find_libelf)
include(find_elfutils)
include(find_linenoise)
include(find_json-c)
include(find_usdt)
include(find_cunit)
include(find_gtk)

#message(STATUS "=== CMAKE_MODULE_PATH: ${CMAKE_MODULE_PATH}")
#message(STATUS "=== CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
#message(STATUS "=== CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")

if(ELFUTILS_INCLUDE_DIRS)
message(STATUS "=== FOUND elfutils-devel")
endif()
if(LIBELF_FOUND)
message(STATUS "=== FOUND libelf")
endif()
if(LIBLINENOISE_FOUND)
message(STATUS "=== FOUND linenoise")
endif()
if(JSON_C_INCLUDE_DIRS)
message(STATUS "=== FOUND json-c devel")
endif()

set(UTILS_FLAGS)
if(ELFUTILS_INCLUDE_DIRS)
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_ELFUTILS_DEVEL)
endif()
if(HAVE_LINENOISE)
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_LINENOISE)
endif()
if(HAVE_JSON_C_H)
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_JSON_C_H)
endif()
if(JSON_C_LIBRARIES)
	message(STATUS "=== FOUND json-c library")
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_JSON_C_LIBRARIES)
endif()
if(HAVE_SDT_H)
	message(STATUS "=== FOUND sdt.h")
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_SDT_H)
endif()
if(HAVE_SDT_DTRACE_PROBE)
	message(STATUS "=== HAVE_SDT_DTRACE_PROBE")
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_SDT_DTRACE_PROBE)
endif()
if(HAVE_GTK_3_0_H)
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_GTK_3_0_H)
endif()

set(TESTS_FLAGS)
if(CUNIT_INCLUDE_DIRS)
	message(STATUS "=== FOUND CUnit Dev")
	set(TESTS_FLAGS "${TESTS_FLAGS}" HAVE_CUNIT)
endif()
if(HAVE_CUNIT_BASIC)
	set(TESTS_FLAGS "${TESTS_FLAGS}" HAVE_CUNIT_BASIC)
endif()

add_subdirectory(src)

if(BUILD_TESTING)
add_subdirectory(tests)
endif()

# install targets
install(
TARGETS
	uftrace
	upatch
	utask
	elfshow
	elftools_test
RUNTIME DESTINATION /usr/local/bin
)

# uninstall targets
if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

