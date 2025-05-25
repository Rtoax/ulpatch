// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include "utils/log.h"
#include "utils/list.h"
#include "utils/utils.h"
#include "elf/elf-api.h"
#include "tests/test-api.h"


#define USR_BIN_LS "/usr/bin/ls"

static const char *test_files[] = {
	USR_BIN_LS,
	"/etc/os-release",
};

static const char *test_files_regular[] = {
	USR_BIN_LS,
};


TEST(Utils_file, fexist, 0)
{
	int ret = 0, i;

	for (i = 0; i < ARRAY_SIZE(test_files); i++) {
		if (!fexist(test_files[i])) {
			ret = -1;
		}
	}

	return ret;
}

TEST(Utils_file, fregular, 0)
{
	int ret = 0, i;

	for (i = 0; i < ARRAY_SIZE(test_files_regular); i++) {
		if (!fregular(test_files_regular[i])) {
			ret = -1;
		}
	}

	return ret;
}

TEST(Utils_file, fsize, 0)
{
	int ret = 0, i;

	for (i = 0; i < ARRAY_SIZE(test_files); i++) {
		if (!fexist(test_files[i]))
			continue;

		int size = fsize(test_files[i]);

		if (size <= 0) {
			ret = -1;
		}
	}

	return ret;
}

TEST(Utils_file, ftouch_remove, 0)
{
	int ret = 0, i;
	char *files[] = {
		"a",
		"b",
		"c",
	};

	for (i = 0; i < ARRAY_SIZE(files); i++) {
		ret |= ftouch(files[i], 0);
		ret |= fremove(files[i]);
	}

	for (i = 0; i < ARRAY_SIZE(files); i++) {
		ret |= ftouch(files[i], 0);
		ret |= fremove_recursive(files[i]);
	}

	return ret;
}

TEST(Utils_file, fmmap_rdonly, 0)
{
	int ret = 0, i;

	for (i = 0; i < ARRAY_SIZE(test_files); i++) {
		if (!fexist(test_files[i]))
			continue;

		struct mmap_struct *mem = fmmap_rdonly(test_files[i]);

		if (!mem) {
			ret = -1;
			break;
		}
		fmunmap(mem);
	}

	return ret;
}

TEST(Utils_file, ftype_ELF, 0)
{
	if (!fexist(USR_BIN_LS)) {
		ulp_error("%s not exist.\n", USR_BIN_LS);
		return -1;
	}

	file_type type = ftype(USR_BIN_LS);
	if ((type & FILE_ELF) != FILE_ELF) {
		ulp_error("%s is not ELF(%d), but %d\n", USR_BIN_LS, FILE_ELF, type);
		return -1;
	}

	return 0;
}

TEST(Utils_file, fmktempfile, 0)
{
	int err = 0;
	char buffer[PATH_MAX];

	char *name;

	/* Create /tmp/xxx file */
	name = fmktempfile(buffer, PATH_MAX, NULL);
	if (!name)
		err = -1;
	ulp_info("fmktempfile: %s\n", name);

	if (!fexist(name))
		err = -EEXIST;

	unlink(name);

	/* Create patch-xxx file */
	name = fmktempfile(buffer, PATH_MAX, "patch-XXXXXX");
	if (!name)
		err = -1;
	ulp_info("fmktempfile: %s\n", name);
	if (!fexist(name))
		err = -EEXIST;

	unlink(name);

	return err;
}

TEST(Utils_file, fmktempname, 0)
{
	int err = 0;
	char buffer[PATH_MAX];

	char *name;

	name = fmktempname(buffer, PATH_MAX, NULL);
	if (!name)
		err = -1;
	ulp_info("fmktempname: %s\n", name);

	name = fmktempname(buffer, PATH_MAX, "patch-XXXXXX");
	if (!name)
		err = -1;
	ulp_info("fmktempname: %s\n", name);

	return err;
}

TEST(Utils_file, fcopy_NULL, -EINVAL)
{
	return fcopy(NULL, NULL);
}

TEST(Utils_file, fcopy_EXIST, -EEXIST)
{
	/* Make sure NOT exist */
	return fcopy("/a/b/c/d/e/f/g/h/i", "/j/k/l/m/n/o/p");
}

TEST(Utils_file, fcopy, 0)
{
#define TMP_FILE	"./a.out"

	int ret;

	ret = fcopy(USR_BIN_LS, TMP_FILE);

	if (!fexist(TMP_FILE)) {
		ulp_error("%s not exist after copy.\n", TMP_FILE);
		ret = -1;
	}
	if (fsize(USR_BIN_LS) != fsize(TMP_FILE)) {
		ulp_error("file size not equal %d != %d.\n",
			fsize(USR_BIN_LS), fsize(TMP_FILE));
		ret = -1;
	}
	unlink(TMP_FILE);
#undef TMP_FILE
	return ret;
}

TEST(Utils_file, fprint_file, 0)
{
	fprint_file(stdout, "/etc/os-release");
	fprint_file(stdout, "/proc/self/maps");
	return 0;
}

static void assert_dir_iter(const char *name, void *arg)
{
	if (!name)
		ulp_error("Utils_file.dir_iter failed.\n");
}

TEST(Utils_file, dir_iter, 0)
{
	return dir_iter("/etc/", assert_dir_iter, NULL);
}
