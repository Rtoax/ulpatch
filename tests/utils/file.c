#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <elf/elf_api.h>

#include "../test_api.h"

static const char *test_files[] = {
	"/usr/bin/ls",
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

