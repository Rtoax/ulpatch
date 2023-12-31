// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/compiler.h>

#include <elf/elf_api.h>

#include "../test_api.h"


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


TEST(Elf,	open_close,	0)
{
	int i;
	int ret = 0;

	for (i = 0; i < ARRAY_SIZE(test_elfs); i++) {
		if (!fexist(test_elfs[i]))
			continue;

		struct elf_file __unused *e = elf_file_open(test_elfs[i]);

		if (!e) {
			lerror("open %s failed.\n", test_elfs[i]);
			ret = -1;
			break;
		}

		elf_file_close(test_elfs[i]);
	}

	return ret;
}

