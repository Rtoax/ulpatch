// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/compiler.h>

#include <elf/elf-api.h>

#include <tests/test-api.h>

TEST_STUB(elf_symbol);

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
	fprint_symbol(stdout, "PFX: ", sym, firstline);
	firstline = false;
}

TEST(Elf_Sym, for_each_symbol, 0)
{
	int ret;
	struct elf_file *elf;
	elf = elf_file_open(ulpatch_test_path);
	if (!elf) {
		ulp_error("open %s failed.\n", ulpatch_test_path);
		return -ENOENT;
	}

	ret = for_each_symbol(elf, print_elf_symbol, NULL);

	elf_file_close(ulpatch_test_path);
	return ret;
}

TEST(Elf_Sym, find_symbols, 0)
{
	int ret = 0;
	int is;

	if (!fexist(ulpatch_test_path))
		return -EEXIST;

	struct elf_file *elf;

	elf = elf_file_open(ulpatch_test_path);
	if (!elf) {
		ulp_error("open %s failed.\n", ulpatch_test_path);
		ret = -1;
		return -EINVAL;
	}

	/* Try find some sym_funcs */
	for (is = 0; is < ARRAY_SIZE(sym_funcs); is++) {
		struct symbol *s;
		s = find_symbol(elf, sym_funcs[is].s, STT_FUNC);
		if (!s) {
			ulp_warning("no symbol %s founded in %s.\n",
				    sym_funcs[is].s, ulpatch_test_path);
			if (sym_funcs[is].must_has) {
				ret = -1;
				break;
			}
		} else {
			ulp_info("%s: %s: st_value: %lx\n",
				 ulpatch_test_path, sym_funcs[is].s,
				 s->sym.st_value);
		}
	}

	elf_file_close(ulpatch_test_path);
	return ret;
}

TEST(Elf_Sym, find_mcount, 0)
{
	int ret = 0;
	struct elf_file *elf;
	const char *mcount_name;
	struct symbol *s;

	/**
	 * test ftrace compile with -pg, thus ulpatch_test_path has mcount
	 * for sure.
	 */
	elf = elf_file_open(ulpatch_test_path);
	if (!elf) {
		ulp_error("open %s failed.\n", ulpatch_test_path);
		ret = -1;
		goto finish;
	}

	if (!elf_support_ftrace(elf))
		goto finish_close_elf;

	mcount_name = elf_mcount_name(elf);
	if (!mcount_name)
		return -ENOENT;

	s = find_symbol(elf, mcount_name, STT_FUNC);
	if (!s) {
		ulp_warning("no symbol %s founded in %s.\n", mcount_name,
			 ulpatch_test_path);
		s = find_undef_symbol(elf, mcount_name, STT_FUNC);
		if (!s) {
			ret = -1;
			goto finish_close_elf;
		}
	}

	ulp_info("%s: %s: st_value: %lx\n", ulpatch_test_path, mcount_name,
		 s->sym.st_value);

finish_close_elf:
	elf_file_close(ulpatch_test_path);

finish:
	return ret;
}

