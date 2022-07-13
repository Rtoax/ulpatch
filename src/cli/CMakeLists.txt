CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

PROJECT(libelfview_cli)

include_directories(..)

find_library(PTHREAD pthread /usr/lib64)
if(HAVE_LINENOISE)
	find_library(LINENOISE linenoise /usr/lib64)
endif()

link_libraries(${ELF} ${PTHREAD} ${LINENOISE} elfview_utils elfview_elf)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

aux_source_directory(. LIB_SOURCES)

add_library(elfview_cli STATIC ${LIB_SOURCES})

target_compile_definitions(elfview_cli PRIVATE ${UTILS_FLAGS})
