# SPDX-License-Identifier: GPL-2.0-or-later
message(STATUS "Compile tests hello")
add_custom_command(
	OUTPUT make-hello.log
	COMMAND make
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/hello/
)
add_custom_target(tests_hello ALL DEPENDS make-hello.log)
