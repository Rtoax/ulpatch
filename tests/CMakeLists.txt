
include_directories(../)
include_directories(../src)

find_library(ELF elf /usr/lib64)
find_library(PTHREAD pthread /usr/lib64)

link_libraries(${ELF} ${PTHREAD}
	elfview_elf
	elfview_utils
	elfview_cli
)

add_definitions(-MD -Wall -Werror -g -ggdb -pg -O2 -D_GNU_SOURCE
	-Wuninitialized -Wreturn-type)

aux_source_directory(. DIR_SRCS)
aux_source_directory(elf DIR_ELF_SRCS)

add_executable(elfview_test
	${DIR_SRCS} ${DIR_ELF_SRCS}
)

target_compile_definitions(elfview_test PRIVATE ${TESTS_FLAGS} ${UTILS_FLAGS})
