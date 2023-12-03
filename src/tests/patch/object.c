// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <elf/elf_api.h>
#include <patch/patch.h>

#include "../test_api.h"


/* see: root CMakeLists.txt */
static const struct upatch_object {
	enum patch_type type;
	char *path;
} upatch_objs[] = {
	/* /usr/share/upatch/upatch-hello.obj */
	{UPATCH_TYPE_PATCH,	UPATCH_HELLO_OBJ_PATH},
};


TEST(Object,	check_object,	0)
{
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(upatch_objs); i++) {

		struct load_info info = {};
		enum patch_type expect_type = upatch_objs[i].type;
		char *obj = upatch_objs[i].path;
		char *tmpfile = "copy.obj";

		if (!fexist(obj)) {
			ret = -EEXIST;
			fprintf(stderr, "\n%s is not exist, maybe: make install\n", obj);
		}
		ret = parse_load_info(obj, tmpfile, &info);
		if (ret) {
			fprintf(stderr, "Parse %s failed.\n", obj);
			return ret;
		}

		setup_load_info(&info);

		/* see UPATCH_INFO() macro */
		if (info.info->pad[0] != 1 || \
			info.info->pad[1] != 2 || \
			info.info->pad[2] != 3 || \
			info.info->pad[3] != 4) {
			fprintf(stderr, "Get wrong pad 0-3.\n");
			return 0;
		}

		if (info.type != expect_type) {
			fprintf(stderr, "Unknow patch type %d(expect %d).\n",
				info.type, expect_type);
			return -1;
		}
	}

	return ret;
}

