// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <errno.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/compiler.h>
#include <elf/elf-api.h>
#include <tests/test-api.h>


static const char *test_elfs[] = {
	"/usr/bin/at",
	"/usr/bin/attr",
	"/usr/bin/awk",
	"/usr/bin/bash",
	"/usr/bin/cat",
	"/usr/bin/grep",
	"/usr/bin/ls",
	"/usr/bin/mv",
	"/usr/bin/sed",
	"/usr/bin/w",
	"/usr/bin/wc",
	"/usr/bin/who",
};


TEST(Elf_Open, open_find_close, 0)
{
	int i;
	int ret = 0;
	struct elf_file *e, *find;

	for (i = 0; i < ARRAY_SIZE(test_elfs); i++) {
		if (!fexist(test_elfs[i]))
			continue;

		e = elf_file_open(test_elfs[i]);
		if (!e) {
			ulp_error("open %s failed.\n", test_elfs[i]);
			ret = -1;
			break;
		}
		find = elf_file_find(test_elfs[i]);
		if (!find) {
			ulp_error("find %s failed.\n", test_elfs[i]);
			ret = -1;
			break;
		}

		if (e != find)
			ret = -1;

		elf_file_close(test_elfs[i]);
	}

	return ret;
}
