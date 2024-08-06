// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/compiler.h>

#include <elf/elf_api.h>

#include <tests/test_api.h>


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

static const struct symbol_t sym_funcs[] = {
	{"__libc_start_main", true},
	{"main", false},
	{MCOUNT, false},
};

static void print_elf_symbol(struct elf_file *elf, struct symbol *sym,
			     void *arg)
{
	int i;
	static bool firstline = true;

	fprint_sym(stdout, &sym->sym, sym->name, NULL, firstline);
	if (sym->nphdrs > 0) {
		for (i = 0; i < sym->nphdrs; i++)
			print_phdr(stdout, &sym->phdrs[i], i == 0);
	}

	firstline = false;
}

TEST(Elf, for_each_symbol, 0)
{
	struct elf_file *elf;
	elf = elf_file_open(ulpatch_test_path);
	if (!elf) {
		lerror("open %s failed.\n", ulpatch_test_path);
		return -ENOENT;
	}

	for_each_symbol(elf, print_elf_symbol, NULL);

	elf_file_close(ulpatch_test_path);
	return 0;
}

TEST(Elf, find_symbol, 0)
{
	int i;
	int ret = 0;

	for (i = 0; i < ARRAY_SIZE(test_elfs); i++) {
		if (!fexist(test_elfs[i]))
			continue;

		struct elf_file *elf;

		elf = elf_file_open(test_elfs[i]);
		if (!elf) {
			lerror("open %s failed.\n", test_elfs[i]);
			ret = -1;
			break;
		}

		/* Try find some sym_funcs */
		int is;
		for (is = 0; is < ARRAY_SIZE(sym_funcs); is++) {
			struct symbol *s;
			s = find_symbol(elf, sym_funcs[is].s, STT_FUNC);
			if (!s) {
				lwarning("no symbol %s founded in %s.\n",
					sym_funcs[is].s, test_elfs[i]);
				if (sym_funcs[is].must_has) {
					ret = -1;
					break;
				}
			} else {
				linfo("%s: %s: st_value: %lx\n",
					test_elfs[i], sym_funcs[is].s, s->sym.st_value);
			}
		}

		elf_file_close(test_elfs[i]);
	}

	return ret;
}

TEST(Elf, find_symbol_mcount, 0)
{
	int ret = 0;
	struct elf_file *elf;

	elf = elf_file_open(ulpatch_test_path);
	if (!elf) {
		lerror("open %s failed.\n", ulpatch_test_path);
		ret = -1;
		goto finish;
	}

	struct symbol *s = find_symbol(elf, MCOUNT, STT_FUNC);
	if (!s) {
		lwarning("no symbol %s founded in %s.\n",
			MCOUNT, ulpatch_test_path);
		ret = -1;
		goto finish_close_elf;
	}

	linfo("%s: %s: st_value: %lx\n",
		ulpatch_test_path, MCOUNT, s->sym.st_value);

finish_close_elf:
	elf_file_close(ulpatch_test_path);

finish:
	return ret;
}

