// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <elf/elf_api.h>

#include "../test_api.h"

#define USR_BIN_LS "/usr/bin/ls"

static const char *test_files[] = {
	USR_BIN_LS,
	"/etc/os-release",
};


TEST(File,	fexist,	0)
{
	int ret = 0, i;

	for (i = 0; i < ARRAY_SIZE(test_files); i++) {
		if (!fexist(test_files[i])) {
			ret = -1;
		}
	}

	return ret;
}

TEST(File,	fsize,	0)
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

TEST(File,	ftouch_remove,	0)
{
	int ret = 0, i;
	char *files[] = {
		"a",
		"b",
		"c",
	};

	for (i = 0; i < ARRAY_SIZE(files); i++) {
		ret |= ftouch(files[i]);
		ret |= fremove(files[i]);
	}

	return ret;
}

TEST(File,	fmmap_rdonly,	0)
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

TEST(File,	ftype_ELF,	0)
{
	if (!fexist(USR_BIN_LS)) {
		lerror("%s not exist.\n", USR_BIN_LS);
		return -1;
	}

	file_type type = ftype(USR_BIN_LS);
	if ((type & FILE_ELF) != FILE_ELF) {
		lerror("%s is not ELF(%d), but %d\n", USR_BIN_LS, FILE_ELF, type);
		return -1;
	}

	return 0;
}

TEST(File,	fmktempfile,	0)
{
	int err = 0;
	char buffer[PATH_MAX];

	char *name;

	/* Create /tmp/xxx file */
	name = fmktempfile(buffer, PATH_MAX, NULL);
	if (!name)
		err = -1;
	linfo("fmktempfile: %s\n", name);

	if (!fexist(name))
		err = -EEXIST;

	unlink(name);

	/* Create /tmp/patch-xxx file */
	name = fmktempfile(buffer, PATH_MAX, "patch-XXXXXX");
	if (!name)
		err = -1;
	linfo("fmktempfile: %s\n", name);
	if (!fexist(name))
		err = -EEXIST;

	unlink(name);

	return err;
}

TEST(File,	fmktempname,	0)
{
	int err = 0;
	char buffer[PATH_MAX];

	char *name;

	name = fmktempname(buffer, PATH_MAX, NULL);
	if (!name)
		err = -1;
	linfo("fmktempname: %s\n", name);

	name = fmktempname(buffer, PATH_MAX, "patch-XXXXXX");
	if (!name)
		err = -1;
	linfo("fmktempname: %s\n", name);

	return err;
}

TEST(File,	fcopy_NULL,	-EINVAL)
{
	return fcopy(NULL, NULL);
}

TEST(File,	fcopy_EXIST,	-EEXIST)
{
	/* Make sure NOT exist */
	return fcopy("/a/b/c/d/e/f/g/h/i", "/j/k/l/m/n/o/p");
}

TEST(File,	fcopy,	0)
{
#define TMP_FILE	"./a.out"

	int ret;

	ret = fcopy(USR_BIN_LS, TMP_FILE);

	if (!fexist(TMP_FILE)) {
		lerror("%s not exist after copy.\n", TMP_FILE);
		ret = -1;
	}

	if (fsize(USR_BIN_LS) != fsize(TMP_FILE)) {
		lerror("file size not equal %d != %d.\n",
			fsize(USR_BIN_LS), fsize(TMP_FILE));
		ret = -1;
	}

	unlink(TMP_FILE);

#undef TMP_FILE

	return ret;
}

