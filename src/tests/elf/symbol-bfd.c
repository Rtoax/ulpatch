// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <string.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <elf/elf-api.h>

#include <utils/util.h>
#include <tests/test-api.h>

TEST_STUB(elf_symbol_bfd);

static const char *test_files[] = {
	"/usr/bin/ls",
	"/usr/bin/cat",
	"/usr/bin/grep",
	"/usr/bin/vim",
#define S_ULPATCH_TEST_PATH	"000"
	S_ULPATCH_TEST_PATH, /* for ulpatch_test_path */
#define S_LIBC_PATH	"001"
	S_LIBC_PATH, /* for libc.so */
};

#define MODIFY_TEST_FILES(i) \
	if (!strcmp(test_files[i], S_ULPATCH_TEST_PATH)) { \
		test_files[i] = ulpatch_test_path; \
	} \
	if (!strcmp(test_files[i], S_LIBC_PATH)) { \
		test_files[i] = libc_object(); \
	}


TEST(Bfd_sym, elf_not_exist, 0)
{
	int ret = -1;
	struct bfd_elf_file *file;

	file = bfd_elf_open("/a/b/c/d/e/f/g/h/i/j/k/l/m");
	if (!file) {
		ret = 0;
	} else {
		bfd_elf_close(file);
	}

	return ret;
}

TEST(Bfd_sym, buildid, 0)
{
	int ret = 0, i;
	struct bfd_elf_file *file, *open_again;
	size_t refcount;
	char buf[512];

	for (i = 0; i < ARRAY_SIZE(test_files); i++) {

		MODIFY_TEST_FILES(i);

		if (!fexist(test_files[i]))
			continue;

		file = bfd_elf_open(test_files[i]);
		open_again = bfd_elf_open(test_files[i]);
		if (!file || !open_again || file != open_again) {
			ret = -1;
		} else {
			refcount = bfd_elf_file_refcount(file);
			if (refcount != 2) {
				ulp_error("refcount = %ld, %s\n", refcount,
					  bfd_elf_file_name(file));
				ret = -1;
			}

			ulp_info("%s Build ID %s\n", test_files[i],
				 bfd_strbid(bfd_elf_bid(file), buf, sizeof(buf)));

			bfd_elf_close(file);
		}
	}

	return ret;
}

TEST(Bfd_sym, for_each_sym, 0)
{
	int ret = 0, i;
	struct bfd_elf_file *file;
	struct bfd_sym *symbol;

	for (i = 0; i < ARRAY_SIZE(test_files); i++) {

		MODIFY_TEST_FILES(i);

		if (!fexist(test_files[i]))
			continue;

		file = bfd_elf_open(test_files[i]);
		if (!file) {
			ret = -1;
			continue;
		}

		for (symbol = bfd_next_plt_sym(file, NULL); symbol;
			symbol = bfd_next_plt_sym(file, symbol)) {

			/* search the address again, double check */
			unsigned long addr = bfd_elf_plt_sym_addr(file,
							bfd_sym_name(symbol));
			unsigned long addr2 = bfd_sym_addr(symbol);

			ulp_debug("plt: %08lx %s (%08lx)\n", addr2,
				  bfd_sym_name(symbol), addr);

			if (addr != addr2)
				ret = -1;
		}

		for (symbol = bfd_next_text_sym(file, NULL); symbol;
			symbol = bfd_next_text_sym(file, symbol)) {

			/* search the address again, double check */
			unsigned long addr = bfd_elf_text_sym_addr(file,
							bfd_sym_name(symbol));
			unsigned long addr2 = bfd_sym_addr(symbol);

			ulp_debug("text: %08lx %s (%08lx)\n", addr2,
				  bfd_sym_name(symbol), addr);

			if (addr != addr2)
				ret = -1;
		}

		for (symbol = bfd_next_data_sym(file, NULL); symbol;
			symbol = bfd_next_data_sym(file, symbol)) {

			/* search the address again, double check */
			unsigned long addr = bfd_elf_data_sym_addr(file,
							bfd_sym_name(symbol));
			unsigned long addr2 = bfd_sym_addr(symbol);

			ulp_debug("data: %08lx %s (%08lx)\n", addr2,
				  bfd_sym_name(symbol), addr);

			if (addr != addr2)
				ret = -1;
		}

		bfd_elf_close(file);
	}

	return ret;
}

static int objdump_plt_sym(struct bfd_elf_file *efile, const char *file)
{
	FILE *fp;
	int ret = 0;
	char cmd[BUFFER_SIZE], line[BUFFER_SIZE];

	/**
	 * $ objdump -d test
	 * [...]
	 * 0000000000403030 <gelf_getehdr@plt>:
	 *
	 * $ objdump -d test | grep @plt | grep ^0
	 */
	snprintf(cmd, BUFFER_SIZE, "objdump -d %s | grep @plt | grep ^0", file);

	fp = popen(cmd, "r");

	while (1) {
		unsigned long addr, addr2;
		char sym[256];
		int ret;

		if (!fgets(line, sizeof(line), fp))
			break;

		ret = sscanf(line, "%lx %s", &addr, sym);
		if (ret <= 0) {
			ulp_error("sscanf failed.\n");
			continue;
		}

		/**
		 * 0000000000403030 <gelf_getehdr@plt>:
		 * ^^^^^^^^^^^^^^^^ addr
		 *                   ^^^^^^^^^^^^ sym
		 */
		/* skip '<' */
		char *s = sym + 1;
		int slen = strlen(s);

		if (!strstr(s, "@plt>:")) {
			ulp_error("Wrong format: %s\n", sym);
			continue;
		}

		s[slen - strlen("@plt>:")] = '\0';

		ulp_info("%s: %#08lx %s\n", basename(file), addr, s);

		addr2 = bfd_elf_plt_sym_addr(efile, s);
		if (addr2 == 0) {
			ulp_warning("Not found symbol %s\n", s);
			ret = -1;
			goto close_return;
		}
		if (addr2 != 0 && addr != addr2) {
			ulp_error("Wrong %s@plt check: %#08lx != %#08lx\n",
				  s, addr, addr2);
			ret = -1;
			goto close_return;
		}
	}

close_return:
	pclose(fp);
	return ret;
}

TEST(Bfd_sym, objdump_plt_sym_addr, 0)
{
	int ret = 0, i;
	struct bfd_elf_file *file;

	for (i = 0; i < ARRAY_SIZE(test_files); i++) {

		MODIFY_TEST_FILES(i);

		if (!fexist(test_files[i]))
			continue;

		file = bfd_elf_open(test_files[i]);
		if (!file) {
			ret = -1;
		} else {
			ret = objdump_plt_sym(file, test_files[i]);
			bfd_elf_close(file);
		}
	}

	return ret;
}

