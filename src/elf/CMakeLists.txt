
include_directories(..)

find_library(ELF elf /usr/lib64)
find_library(PTHREAD pthread /usr/lib64)

set(JSON_C)
if(JSON_C_LIBRARIES)
find_library(JSON_C json-c /usr/lib64)
endif()

link_libraries(${ELF} ${PTHREAD} ${JSON_C} elfview_utils)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

file( GLOB LIB_SOURCES
	elf_main.c
	elf_client.c
	elf_open.c
	elf_get.c
	ehdr.c
	phdr.c
	shdr.c
	test.c
)

add_library(elfview_elf STATIC ${LIB_SOURCES})

target_compile_definitions(elfview_elf PRIVATE ${UTILS_FLAGS})
