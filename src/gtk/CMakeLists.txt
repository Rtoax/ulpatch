
find_package(PkgConfig REQUIRED)

include_directories(.)

#pkg_search_module(GTK_3_0 REQUIRED gtk+-3.0)

#message(STATUS "=== GTK_3_0_LIBRARIES: ${GTK_3_0_LIBRARIES}")
#message(STATUS "=== GTK_3_0_INCLUDE_DIRS: ${GTK_3_0_INCLUDE_DIRS}")

#include_directories(${GTK_3_0_INCLUDE_DIRS})


link_libraries(${ELF} ${RT} ${PTHREAD}
	elfview_utils
	elfview_elf
	elfview_cli
)
add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type -pg)

aux_source_directory(. LIB_SOURCES)

add_library(elfview_gtk STATIC ${LIB_SOURCES})

target_compile_definitions(elfview_gtk PRIVATE ${UTILS_FLAGS})
