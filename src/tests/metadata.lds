/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2025 Rong Tao */
SECTIONS
{
	.data.ulpatch.metadata : {
		/* . = ALIGN(4);*/
		test_meta_start = .;
		/* see test-api.h macro __test_metadata, store struct test {} */
		*(.data.ulpatch.test.metadata*)
		test_meta_end = .;
	}
}
INSERT AFTER .data;
