# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2025 Rong Tao
#
include_directories(../..)

message(STATUS "Compile for x86_64")

add_library(ulpatch_arch STATIC
	alternative.c
	ftrace.c
	insn.c
	patch.c
	mcount.S
)

target_compile_definitions(ulpatch_arch PRIVATE ${UTILS_CFLAGS_MACROS})
