// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/compiler.h>

#include <elf/elf_api.h>

#include <tests/test_api.h>


struct symbol_t {
	const char *s;
	bool must_has;
};

static const struct symbol_t sym_funcs[] = {
	{"main", true},
};

static void print_elf_symbol(struct elf_file *elf, struct symbol *sym,
			     void *arg)
{
	static bool firstline = true;
	fprint_symbol(stdout, sym, firstline);
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
	int ret = 0;

	if (!fexist(ulpatch_test_path))
		return -EEXIST;

	struct elf_file *elf;

	elf = elf_file_open(ulpatch_test_path);
	if (!elf) {
		lerror("open %s failed.\n", ulpatch_test_path);
		ret = -1;
		return -EINVAL;
	}

	/* Try find some sym_funcs */
	int is;
	for (is = 0; is < ARRAY_SIZE(sym_funcs); is++) {
		struct symbol *s;
		s = find_symbol(elf, sym_funcs[is].s, STT_FUNC);
		if (!s) {
			lwarning("no symbol %s founded in %s.\n",
				sym_funcs[is].s, ulpatch_test_path);
			if (sym_funcs[is].must_has) {
				ret = -1;
				break;
			}
		} else {
			linfo("%s: %s: st_value: %lx\n",
				ulpatch_test_path, sym_funcs[is].s, s->sym.st_value);
		}
	}

	elf_file_close(ulpatch_test_path);

	return ret;
}

TEST(Elf, find_symbol_mcount, 0)
{
	int ret = 0;
	struct elf_file *elf;
	const char *mcount_name;

	elf = elf_file_open(ulpatch_test_path);
	if (!elf) {
		lerror("open %s failed.\n", ulpatch_test_path);
		ret = -1;
		goto finish;
	}

	if (!elf_support_ftrace(elf))
		goto finish_close_elf;

	mcount_name = elf_mcount_name(elf);
	if (!mcount_name)
		return -ENOENT;

	struct symbol *s = find_symbol(elf, mcount_name, STT_FUNC);
	if (!s) {
		lwarning("no symbol %s founded in %s.\n", mcount_name,
			 ulpatch_test_path);
		ret = -1;
		goto finish_close_elf;
	}

	linfo("%s: %s: st_value: %lx\n", ulpatch_test_path, mcount_name,
	      s->sym.st_value);

finish_close_elf:
	elf_file_close(ulpatch_test_path);

finish:
	return ret;
}

