
include_directories(..)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

if(HAVE_LINENOISE)
	set(LINENOISE_SRC)
else()
	aux_source_directory(linenoise LINENOISE_SRC)
endif()

aux_source_directory(. LIB_SOURCES)

add_library(elftools_utils STATIC ${LIB_SOURCES} ${LINENOISE_SRC})

target_compile_definitions(elftools_utils PRIVATE ${UTILS_FLAGS})
