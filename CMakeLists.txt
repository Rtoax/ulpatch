# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com>

CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

PROJECT(ulpatch)

# Version number components. You _MUST_ modify ulpatch.spec file at the same,
# if you modify the following three lines.
set(ULPATCH_VERSION_MAJOR 0)
set(ULPATCH_VERSION_MINOR 5)
set(ULPATCH_VERSION_PATCH 6)

execute_process(
	COMMAND git describe --abbrev=4 --dirty --tags
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	OUTPUT_VARIABLE ULPATCH_VERSION
	ERROR_VARIABLE GIT_DESCRIBE_ERROR
	OUTPUT_STRIP_TRAILING_WHITESPACE
	RESULT_VARIABLE retcode
)

# If the build is not done from a git repo, get the version information from
# the version variables in main CMakeLists.txt
if(NOT "${retcode}" STREQUAL "0")
set(ULPATCH_VERSION "v${ULPATCH_VERSION_MAJOR}.${ULPATCH_VERSION_MINOR}.${ULPATCH_VERSION_PATCH}")
endif()

add_definitions("-DULPATCH_VERSION_MAJOR=${ULPATCH_VERSION_MAJOR}")
add_definitions("-DULPATCH_VERSION_MINOR=${ULPATCH_VERSION_MINOR}")
add_definitions("-DULPATCH_VERSION_PATCH=${ULPATCH_VERSION_PATCH}")
add_definitions("-DULPATCH_VERSION=\"${ULPATCH_VERSION}\"")

EXECUTE_PROCESS(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)
set(WARNINGS_AS_ERRORS OFF CACHE BOOL "Build with -Werror")
# If you modify, update docs/INSTALL.md
set(BUILD_TESTING ON CACHE BOOL "Build test suite")
set(BUILD_ULFTRACE ON CACHE BOOL "Build ulftrace")
set(BUILD_ULTASK ON CACHE BOOL "Build ultask")
set(BUILD_MAN ON CACHE BOOL "Build man pages")
set(CMAKE_INSTALL_PREFIX /usr)
set(CMAKE_BUILD_TYPE Debug)

set(ULPATCH_INCLUDE_DIR ${CMAKE_INSTALL_PREFIX}/include/ulpatch/)
set(ULPATCH_SHARE_DIR ${CMAKE_INSTALL_PREFIX}/share/ulpatch/)
# see src/patch/objects/ftrace/CMakeLists.txt
set(FTRACE_MCOUNT_OBJ ftrace-mcount.obj)
# see src/patch/objects/hello/CMakeLists.txt
set(ULPATCH_HELLO_OBJ hello.obj)

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
include(find_libunwind)
include(find_capstone)
include(find_elfutils)
include(find_binutils)
include(find_kernel_headers)

message(STATUS "=== CMAKE_MODULE_PATH: ${CMAKE_MODULE_PATH}")
message(STATUS "=== CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "=== CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")
message(STATUS "=== CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "=== Architecture: ${ARCHITECTURE}")

if(ELFUTILS_INCLUDE_DIRS)
message(STATUS "=== FOUND elfutils-devel")
else()
message(FATAL_ERROR "=== FOUND elfutils-devel")
endif()
if(BINUTILS_INCLUDE_DIRS)
message(STATUS "=== FOUND binutils-devel")
else()
message(FATAL_ERROR "=== Not FOUND binutils-devel")
endif()
if(CAPSTONE_INCLUDE_DIRS)
message(STATUS "=== FOUND capstone-devel")
endif()
if(LIBUNWIND_INCLUDE_DIRS)
message(STATUS "=== FOUND libunwind-devel")
endif()
if(KERNEL_HEADERS_INCLUDE_DIRS)
message(STATUS "=== FOUND kernel-headers")
endif()
if(LIBELF_FOUND)
message(STATUS "=== FOUND libelf")
endif()

set(UTILS_FLAGS)
set(TESTS_FLAGS)

if(ELFUTILS_INCLUDE_DIRS)
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_ELFUTILS_DEVEL)
endif()
if(BINUTILS_INCLUDE_DIRS)
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_BINUTILS_DEVEL)
endif()
if(BINUTILS_BFD_H)
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_BINUTILS_BFD_H)
endif()
if(LIBUNWIND_LIBUNWIND_H)
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_LIBUNWIND_H)
endif()
if(CAPSTONE_INCLUDE_DIRS)
	set(UTILS_FLAGS "${UTILS_FLAGS}" HAVE_CAPSTONE_DEVEL)
endif()
if(CAPSTONE_CAPSTONE_H)
	set(UTILS_FLAGS "${UTILS_FLAGS}" CAPSTONE_CAPSTONE_H)
endif()

if(KERNEL_HEADERS_CONST_H)
	set(UTILS_FLAGS "${UTILS_FLAGS}" KERNEL_HEADERS_CONST_H)
endif()

# macro ULPATCH_FTRACE_OBJ_PATH="/usr/share/ulpatch/ftrace-mcount.obj" for example
set(UTILS_FLAGS "${UTILS_FLAGS}" ULPATCH_FTRACE_OBJ_PATH="${ULPATCH_SHARE_DIR}${FTRACE_MCOUNT_OBJ}")
# macro ULPATCH_HELLO_OBJ_PATH="/usr/share/ulpatch/hello.obj" for example
set(UTILS_FLAGS "${UTILS_FLAGS}" ULPATCH_HELLO_OBJ_PATH="${ULPATCH_SHARE_DIR}${ULPATCH_HELLO_OBJ}")

add_subdirectory(src)

# install targets
if (BUILD_ULFTRACE)
install(TARGETS ulftrace RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
endif()
if (BUILD_ULTASK)
install(TARGETS ultask RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
endif()
install(TARGETS ulpatch RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
install(TARGETS ulpinfo RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
if (BUILD_TESTING)
install(TARGETS ulpatch_test RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
endif()

# install object file
# see src/patch/objects/ftrace/CMakeLists.txt file to modify object file's name
install(DIRECTORY DESTINATION ${ULPATCH_SHARE_DIR})
install(DIRECTORY DESTINATION ${ULPATCH_INCLUDE_DIR})
install(
FILES
	${PROJECT_SOURCE_DIR}/src/patch/meta.h
DESTINATION ${ULPATCH_INCLUDE_DIR}
)
install(
PROGRAMS
	${PROJECT_SOURCE_DIR}/src/patch/objects/ftrace/${FTRACE_MCOUNT_OBJ}
	${PROJECT_SOURCE_DIR}/src/patch/objects/hello/${ULPATCH_HELLO_OBJ}
DESTINATION ${ULPATCH_SHARE_DIR}
)

if (BUILD_MAN)
	set(CMAKE_INSTALL_MANDIR "/usr/share/man/")
	add_subdirectory(man)
endif(BUILD_MAN)

# uninstall targets
if(NOT TARGET uninstall)
	configure_file(
		"${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
		"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
		IMMEDIATE @ONLY)

	add_custom_target(uninstall
		COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

