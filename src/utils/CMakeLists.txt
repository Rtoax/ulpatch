
include_directories(..)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

if(HAVE_LINENOISE)
	set(LINENOISE_SRC)
else()
	set(LINENOISE_SRC linenoise.c)
endif()

file( GLOB LIB_SOURCES
	rbtree.c
	log.c
	daemon.c
	list.c
	version.c
	string.c
	${LINENOISE_SRC}
)

add_library(elfview_utils STATIC ${LIB_SOURCES})

target_compile_definitions(elfview_utils PRIVATE ${UTILS_FLAGS})
