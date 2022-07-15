###################################
## Top level CMakeLists.txt
##
## Author: Rong Tao
###################################
CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

PROJECT(elftools)

set(WARNINGS_AS_ERRORS OFF CACHE BOOL "Build with -Werror")
set(BUILD_TESTING ON CACHE BOOL "Build test suite")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(find_libelf)
include(find_linenoise)
include(find_json-c)
include(find_usdt)
include(find_cunit)
include(find_gtk)

#message(STATUS "=== CMAKE_MODULE_PATH: ${CMAKE_MODULE_PATH}")
#message(STATUS "=== CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
#message(STATUS "=== CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")

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
