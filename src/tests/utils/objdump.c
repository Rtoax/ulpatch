// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <elf/elf_api.h>

#include <utils/util.h>
#include <tests/test_api.h>


static const char *test_files[] = {
	"/usr/bin/ls",
	"/usr/bin/cat",
	"/usr/bin/grep",
	"/usr/bin/vim",
#define S_ULPATCH_TEST_PATH	"0"
	S_ULPATCH_TEST_PATH, // for ulpatch_test_path
};

#define MODIFY_TEST_FILES(i) \
	if (!strcmp(test_files[i], S_ULPATCH_TEST_PATH) == 0) { \
		test_files[i] = ulpatch_test_path; \
	}


TEST(Objdump,	load_nonexist,	0)
{
	int ret = -1;
	struct objdump_elf_file *file;

	file = objdump_elf_load("/a/b/c/d/e/f/g/h/i/j/k/l/m");
	if (!file) {
		ret = 0;
	} else {
		objdump_elf_close(file);
	}

	return ret;
}

TEST(Objdump,	load,	0)
{
	int ret = 0, i;
	struct objdump_elf_file *file;

	for (i = 0; i < ARRAY_SIZE(test_files); i++) {

		MODIFY_TEST_FILES(i);

		if (!fexist(test_files[i]))
			continue;

		file = objdump_elf_load(test_files[i]);
		if (!file) {
			ret = -1;
		} else {
			objdump_elf_close(file);
		}
	}

	return ret;
}

TEST(Objdump,	for_each_plt_symbol_and_search,	0)
{
	int ret = 0, i;
	struct objdump_elf_file *file;

	for (i = 0; i < ARRAY_SIZE(test_files); i++) {

		MODIFY_TEST_FILES(i);

		if (!fexist(test_files[i]))
			continue;

		file = objdump_elf_load(test_files[i]);
		if (!file) {
			ret = -1;
		} else {

			struct objdump_symbol *symbol;

			for (symbol = objdump_elf_plt_next_symbol(file, NULL);
				symbol;
				symbol = objdump_elf_plt_next_symbol(file, symbol)) {

				/* search the address again, double check */
				unsigned long addr = objdump_elf_plt_symbol_address(file,
								objdump_symbol_name(symbol));
				unsigned long addr2 = objdump_symbol_address(symbol);

				ldebug("%08lx %s (%08lx)\n",
					addr2,
					objdump_symbol_name(symbol),
					addr);

				if (addr != addr2)
					ret = -1;
			}

			objdump_elf_close(file);
		}
	}

	return ret;
}

static int __unused objdump_for_each_plt_sym(struct objdump_elf_file *efile,
				const char *file)
{
	FILE *fp;
	int ret = 0;
	char cmd[BUFFER_SIZE], line[BUFFER_SIZE];

	/* $ objdump -d test
	 *
	 * [...]
	 *
	 * Disassembly of section .plt:
	 *
	 * 0000000000403020 <.plt>:
	 *  403020:	ff 35 e2 9f 01 00    	pushq  0x19fe2(%rip)        # 41d008 <_GLOBAL_OFFSET_TABLE_+0x8>
	 *  403026:	ff 25 e4 9f 01 00    	jmpq   *0x19fe4(%rip)        # 41d010 <_GLOBAL_OFFSET_TABLE_+0x10>
	 *  40302c:	0f 1f 40 00          	nopl   0x0(%rax)
	 *
	 * 0000000000403030 <gelf_getehdr@plt>:
	 *  403030:	ff 25 e2 9f 01 00    	jmpq   *0x19fe2(%rip)        # 41d018 <gelf_getehdr@ELFUTILS_1.0>
	 *  403036:	68 00 00 00 00       	pushq  $0x0
	 *  40303b:	e9 e0 ff ff ff       	jmpq   403020 <.plt>
	 *
	 * To get '0000000000403030 <gelf_getehdr@plt>:':
	 *
	 * $ objdump -d test | grep @plt | grep ^0
	 */
	snprintf(cmd, BUFFER_SIZE,
		"objdump -d %s | grep @plt | grep ^0", file);

	fp = popen(cmd, "r");

	while (1) {
		unsigned long addr;
		char sym[256];
		int ret;

		if (!fgets(line, sizeof(line), fp))
			break;

		ret = sscanf(line, "%lx %s", &addr, sym);
		if (ret <= 0) {
			lerror("sscanf failed.\n");
			continue;
		}

		/* For example:
		 * 0000000000403030 <gelf_getehdr@plt>:
		 *
		 * $addr: 0000000000403030
		 * $sym:  <gelf_getehdr@plt>:
		 */
		char *s = sym + 1;
		int slen = strlen(s);

		if (!strstr(s, "@plt>:")) {
			lerror("Wrong format: %s\n", sym);
			continue;
		}

		s[slen - strlen("@plt>:")] = '\0';

		linfo("%s: %#08lx %s\n", basename(file), addr, s);

		unsigned long addr2 = objdump_elf_plt_symbol_address(efile, s);

		if (addr2 == 0) {
			lwarning("Not found symbol %s\n", s);
			ret = -1;
			goto close_return;
		}
		if (addr2 != 0 && addr != addr2) {
			lerror("Wrong %s@plt check: %#08lx != %#08lx\n",
				s, addr, addr2);
			ret = -1;
			goto close_return;
		}
	}

close_return:
	pclose(fp);

	return ret;
}

TEST(Objdump,	check_each_plt_sym_addr,	0)
{
	int ret = 0, i;
	struct objdump_elf_file *file;

	for (i = 0; i < ARRAY_SIZE(test_files); i++) {

		MODIFY_TEST_FILES(i);

		if (!fexist(test_files[i]))
			continue;

		file = objdump_elf_load(test_files[i]);
		if (!file) {
			ret = -1;
		} else {
			ret = objdump_for_each_plt_sym(file, test_files[i]);

			objdump_elf_close(file);
		}
	}

	return ret;
}

