# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao

CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

if(${CMAKE_VERSION} VERSION_EQUAL 3.12.0 OR ${CMAKE_VERSION} VERSION_GREATER 3.12.0)
	cmake_policy(SET CMP0074 NEW)
endif()

if(${CMAKE_VERSION} VERSION_EQUAL 3.3.0 OR ${CMAKE_VERSION} VERSION_GREATER 3.3.0)
	cmake_policy(SET CMP0057 NEW)
endif()

PROJECT(ulpatch)

enable_language(C ASM)

string(TIMESTAMP ULPATCH_COMPILE_TIME "%Y/%m/%d %H:%M:%S")
message(STATUS "Build in ${ULPATCH_COMPILE_TIME}")

# Version number components. You _MUST_ modify ulpatch.spec file at the same,
# if you modify the following three lines.
set(ULPATCH_VERSION_MAJOR 0)
set(ULPATCH_VERSION_MINOR 5)
set(ULPATCH_VERSION_PATCH 10)

execute_process(
	COMMAND git describe --abbrev=4 --dirty --tags
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	OUTPUT_VARIABLE ULPATCH_VERSION
	ERROR_VARIABLE GIT_DESCRIBE_ERROR
	OUTPUT_STRIP_TRAILING_WHITESPACE
	RESULT_VARIABLE version_retcode
)

# If the build is not done from a git repo, get the version information from
# the version variables in main CMakeLists.txt
if(NOT "${version_retcode}" STREQUAL "0")
	set(ULPATCH_VERSION "v${ULPATCH_VERSION_MAJOR}.${ULPATCH_VERSION_MINOR}.${ULPATCH_VERSION_PATCH}")
endif()

execute_process(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)
cmake_host_system_information(RESULT OS_NAME QUERY OS_NAME)
cmake_host_system_information(RESULT OS_RELEASE QUERY OS_RELEASE)
if(${CMAKE_VERSION} VERSION_EQUAL 3.22 OR ${CMAKE_VERSION} VERSION_GREATER 3.22)
	cmake_host_system_information(RESULT OS_PRETTY_NAME QUERY DISTRIB_PRETTY_NAME)
else()
	set(OS_PRETTY_NAME "${OS_NAME} ${OS_RELEASE}")
endif()

set(WARNINGS_AS_ERRORS ON CACHE BOOL "Build with -Werror")
# If you modify, update docs/INSTALL.md
set(BUILD_TESTING ON CACHE BOOL "Build test suite")
set(BUILD_ULFTRACE ON CACHE BOOL "Build ulftrace")
set(BUILD_ULTASK ON CACHE BOOL "Build ultask")
set(BUILD_MAN ON CACHE BOOL "Build man pages")
set(BUILD_PIE_EXE OFF CACHE BOOL "Build all Executions as PIE")
set(BUILD_WITH_CAPSTONE ON CACHE BOOL "Build with capstone for disasm")

set(CMAKE_INSTALL_PREFIX /usr)
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Debug)
endif()

set(ULPATCH_INCLUDE_DIR ${CMAKE_INSTALL_PREFIX}/include/ulpatch)
set(ULPATCH_SHARE_DIR ${CMAKE_INSTALL_PREFIX}/share/ulpatch)
set(ULPATCH_SHARE_FTRACE_DIR ${ULPATCH_SHARE_DIR}/ftrace)
set(ULPATCH_SHARE_ULPATCHES_DIR ${ULPATCH_SHARE_DIR}/ulpatches)

add_definitions("-DULPATCH_VERSION_MAJOR=${ULPATCH_VERSION_MAJOR}")
add_definitions("-DULPATCH_VERSION_MINOR=${ULPATCH_VERSION_MINOR}")
add_definitions("-DULPATCH_VERSION_PATCH=${ULPATCH_VERSION_PATCH}")
add_definitions("-DULPATCH_VERSION=\"${ULPATCH_VERSION}\"")
add_definitions("-DULPATCH_COMPILE_TIME=\"${ULPATCH_COMPILE_TIME}\"")
add_definitions("-DOS_PRETTY_NAME=\"${OS_PRETTY_NAME}\"")
if (BUILD_ULFTRACE)
	add_definitions("-DBUILD_ULFTRACE=1")
endif()
if (BUILD_ULTASK)
	add_definitions("-DBUILD_ULTASK=1")
endif()
if (BUILD_MAN)
	add_definitions("-DBUILD_MAN=1")
endif()
if (BUILD_TESTING)
	add_definitions("-DBUILD_TESTING=1")
endif()

add_compile_options(-MD)
add_compile_options(-Wall)
if (WARNINGS_AS_ERRORS)
	add_compile_options(-Werror)
endif()
add_compile_options(-D_GNU_SOURCE)
add_compile_options(-Wuninitialized)
add_compile_options(-Wreturn-type)

if(BUILD_PIE_EXE)
	message(STATUS "Turn on PIE")
	set(CMAKE_POSITION_INDEPENDENT_CODE ON)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
else()
	message(STATUS "Turn off PIE")
	set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
endif()

# check processor architecture
# only support x86_64 and aarch64 right now.
if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86_64")
	message(STATUS "x86_64 architecture detected")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "aarch64")
	message(STATUS "aarch64 architecture detected")
else()
	message(FATAL_ERROR "Only support x86_64,aarch64")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(find_libelf)
include(find_libunwind)
include(find_capstone)
include(find_elfutils)
include(find_binutils)
include(find_kernel_headers)

message(STATUS "CMAKE_MODULE_PATH: ${CMAKE_MODULE_PATH}")
message(STATUS "CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")
message(STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Architecture: ${ARCHITECTURE}")
message(STATUS "OS Name: ${OS_NAME}")
message(STATUS "OS Release: ${OS_RELEASE}")
message(STATUS "OS Pretty Name: ${OS_PRETTY_NAME}")


# This variable store utils CFLAGS's macros(-D of compiler)
set(UTILS_CFLAGS_MACROS)
set(TESTS_CFLAGS_MACROS)

if(LIBELF_INCLUDE_DIRS)
	message(STATUS "Found libelf headers")
	set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" HAVE_LIBELF_DEVEL)
endif()

if(ELFUTILS_INCLUDE_DIRS)
	message(STATUS "Found elfutils headers")
	set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" HAVE_ELFUTILS_DEVEL)
else()
	message(FATAL_ERROR "Not found elfutils header")
endif()

if(BINUTILS_INCLUDE_DIRS)
	message(STATUS "Found binutils headers")
	set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" HAVE_BINUTILS_DEVEL)
else()
	message(FATAL_ERROR "Not found binutils headers")
endif()

if(BINUTILS_BFD_H)
	message(STATUS "Found binutils bfd.h")
	set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" HAVE_BINUTILS_BFD_H)
	if(BINUTILS_HAVE_BFD_ELF_BFD_FROM_REMOTE_MEMORY)
		message(STATUS "bfd support bfd_elf_bfd_from_remote_memory()")
	else()
		message(FATAL_ERROR "not support bfd_elf_bfd_from_remote_memory()")
	endif()
	if(BINUTILS_HAVE_BFD_ASYMBOL_SECTION)
		message(STATUS "bfd support bfd_asymbol_section()")
		set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" BINUTILS_HAVE_BFD_ASYMBOL_SECTION)
	endif()
	if(BINUTILS_HAVE_BFD_SECTION_FLAGS)
		message(STATUS "bfd support bfd_section_flags()")
		set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" BINUTILS_HAVE_BFD_SECTION_FLAGS)
	endif()
	if(BINUTILS_HAVE_BFD_SECTION_NAME)
		message(STATUS "bfd support bfd_section_name(asect)")
		set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" BINUTILS_HAVE_BFD_SECTION_NAME)
	endif()
	if(BINUTILS_HAVE_BFD_SECTION_NAME2)
		message(STATUS "bfd support bfd_section_name(abfd, asect)")
		set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" BINUTILS_HAVE_BFD_SECTION_NAME2)
	endif()
else()
	message(FATAL_ERROR "Not found bfd.h")
endif()

# Libunwind provides a C ABI to determine the call-chain of a program.
if(LIBUNWIND_LIBUNWIND_H)
	message(STATUS "Found libunwind headers")
	set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" HAVE_LIBUNWIND_H)
	set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" CONFIG_LIBUNWIND=1)
endif()

# Capstone Disassembler Engine
# Capstone is a disassembly framework with the target of becoming the ultimate
# disasm engine for binary analysis and reversing in the security community.
if(BUILD_WITH_CAPSTONE)
	message(STATUS "Build with capstone support")
	set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" CONFIG_CAPSTONE=1)
	if(CAPSTONE_INCLUDE_DIRS)
		message(STATUS "Found capstone headers")
		set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" HAVE_CAPSTONE_DEVEL)
	else()
		message(FATAL_ERROR "Not found capstone headers")
	endif()

	if(CAPSTONE_CAPSTONE_H)
		set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" HAVE_CAPSTONE_CAPSTONE_H)
	else()
		message(FATAL_ERROR "Not found capstone/capstone.h")
	endif()
else()
	message(STATUS "Build without capstone support")
endif()

if(KERNEL_HEADERS_INCLUDE_DIRS)
	message(STATUS "Found kernel headers")
	set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" HAVE_KERNEL_HEADERS_DEVEL)
endif()

if(KERNEL_HEADERS_CONST_H)
	set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" HAVE_KERNEL_HEADERS_CONST_H)
endif()

set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" ULPATCH_OBJ_FTRACE_MCOUNT_PATH="${ULPATCH_SHARE_FTRACE_DIR}/ftrace-mcount.obj")
set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" ULPATCH_TEST_ULP_EMPTY_PATH="${ULPATCH_SHARE_ULPATCHES_DIR}/empty.ulp")
set(UTILS_CFLAGS_MACROS "${UTILS_CFLAGS_MACROS}" ULPATCH_TEST_ULP_PRINTF_PATH="${ULPATCH_SHARE_ULPATCHES_DIR}/printf.ulp")

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
install(
PROGRAMS
	${CMAKE_CURRENT_BINARY_DIR}/src/ulp-config
DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
)

# install object file
# see src/patch/objects/ftrace/CMakeLists.txt file to modify object file's name
install(DIRECTORY DESTINATION ${ULPATCH_SHARE_DIR})
install(DIRECTORY DESTINATION ${ULPATCH_SHARE_FTRACE_DIR})
install(DIRECTORY DESTINATION ${ULPATCH_SHARE_ULPATCHES_DIR})
install(DIRECTORY DESTINATION ${ULPATCH_INCLUDE_DIR})
install(
FILES
	${PROJECT_SOURCE_DIR}/src/patch/asm.h
	${PROJECT_SOURCE_DIR}/src/patch/meta.h
DESTINATION ${ULPATCH_INCLUDE_DIR}
)
install(
PROGRAMS
	${CMAKE_CURRENT_BINARY_DIR}/src/objects/ftrace/ftrace-mcount.obj
DESTINATION ${ULPATCH_SHARE_FTRACE_DIR}
)
install(
PROGRAMS
	${CMAKE_CURRENT_BINARY_DIR}/src/tests/ulpatches/empty.ulp
	${CMAKE_CURRENT_BINARY_DIR}/src/tests/ulpatches/printf.ulp
DESTINATION ${ULPATCH_SHARE_ULPATCHES_DIR}
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

