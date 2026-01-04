# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Rong Tao
#
message(STATUS "Compile tests bfd")
add_custom_command(
	OUTPUT make-bfd.log
	COMMAND make
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/bfd/
)
add_custom_target(tests_bfd ALL DEPENDS make-bfd.log)
