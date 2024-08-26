# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
include_directories(../..)

message(STATUS "Compile for aarch64")

add_library(ulpatch_arch STATIC
	ftrace.c
	insn.c
	patch.c
)

target_compile_definitions(ulpatch_arch PRIVATE ${UTILS_CFLAGS_MACROS})
