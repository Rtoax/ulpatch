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
	if (type != FILE_ELF) {
		lerror("%s is not ELF(%d), but %d\n", USR_BIN_LS, FILE_ELF, type);
		return -1;
	}

	return 0;
}

