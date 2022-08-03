
add_subdirectory(utils)
add_subdirectory(elf)
add_subdirectory(patch)
add_subdirectory(cli)
add_subdirectory(gtk)

find_package(PkgConfig REQUIRED)

include_directories(.)

#pkg_search_module(GTK_3_0 REQUIRED gtk+-3.0)

#message(STATUS "=== GTK_3_0_LIBRARIES: ${GTK_3_0_LIBRARIES}")
#message(STATUS "=== GTK_3_0_INCLUDE_DIRS: ${GTK_3_0_INCLUDE_DIRS}")

#include_directories(${GTK_3_0_INCLUDE_DIRS})

find_library(ELF elf /usr/lib64)
find_library(RT rt /usr/lib64)
find_library(PTHREAD pthread /usr/lib64)

link_libraries(${ELF} ${RT} ${PTHREAD}
	elftools_utils
	elftools_elf
	elftools_cli
	elftools_gtk
)
add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type -pg)

# Target: elfshow
add_executable(elfshow
	elfshow.c
)
target_compile_definitions(elfshow PRIVATE ${UTILS_FLAGS})

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

