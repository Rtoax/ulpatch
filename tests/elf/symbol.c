// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
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

	/* 'who' has no 'main' symbol */
	"/usr/bin/who",
};

#if defined(__x86_64__)
# define MCOUNT	"mcount"
#elif defined(__aarch64__)
# define MCOUNT	"_mcount"
#endif

struct symbol_t {
	const char *s;
	bool must_has;
};

static const struct symbol_t symbols[] = {
	{"__libc_start_main", true},
	{"main", false},
	{MCOUNT, false},
};


TEST(Elf,	find_symbol,	0)
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

		/* Try find some symbols */
		int is;
		for (is = 0; is < ARRAY_SIZE(symbols); is++) {
			struct symbol *s = find_symbol(e, symbols[is].s);
			if (!s) {
				lwarning("no symbol %s founded in %s.\n",
					symbols[is].s, test_elfs[i]);
				if (symbols[is].must_has) {
					ret = -1;
					break;
				}
			} else {
				linfo("%s: %s: st_value: %lx\n",
					test_elfs[i], symbols[is].s, s->sym.st_value);
			}
		}

		elf_file_close(test_elfs[i]);
	}

	return ret;
}

TEST(Elf,	find_symbol_mcount,	0)
{
	int ret = 0;
	struct elf_file __unused *e = elf_file_open(elftools_test_path);

	if (!e) {
		lerror("open %s failed.\n", elftools_test_path);
		ret = -1;
		goto finish;
	}

	struct symbol *s = find_symbol(e, MCOUNT);
	if (!s) {
		lwarning("no symbol %s founded in %s.\n",
			MCOUNT, elftools_test_path);
		ret = -1;
		goto finish_close_elf;
	}

	linfo("%s: %s: st_value: %lx\n",
		elftools_test_path, MCOUNT, s->sym.st_value);

finish_close_elf:
	elf_file_close(elftools_test_path);

finish:
	return ret;
}

