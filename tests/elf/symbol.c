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
	"/usr/bin/who",
};

static bool file_exist(const char *filepath)
{
	return access(filepath, F_OK) == 0? true:false;
}

TEST(Elf,	find_symbol,	0)
{
	int i;
	int ret = 0;

	for (i = 0; i < ARRAY_SIZE(test_elfs); i++) {
		if (!file_exist(test_elfs[i]))
			continue;

		struct elf_file __unused *e = elf_file_open(test_elfs[i]);

		if (!e) {
			lerror("open %s failed.\n", test_elfs[i]);
			ret = -1;
			break;
		}

#define LIBC_MAIN	"__libc_start_main"
		struct symbol *s = find_symbol(e, LIBC_MAIN);
		if (!s) {
			lerror("no symbol %s founded in %s.\n", LIBC_MAIN, test_elfs[i]);
			elf_file_close(test_elfs[i]);
			ret = -1;
			break;
		}

		elf_file_close(test_elfs[i]);
	}

	return ret;
}

