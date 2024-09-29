# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
set(make_include ${PROJECT_SOURCE_DIR}/src/)
message(STATUS "Compile ulpatch hello ulp ${make_include}")
add_custom_command(
	OUTPUT make-ulpatches.log
	COMMAND make INCS1="-I${make_include}" ULP_CONFIG=${PROJECT_SOURCE_DIR}/src/ulp-config
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/tests/ulpatches
)
add_custom_target(tests_ulpatches ALL DEPENDS make-ulpatches.log)
