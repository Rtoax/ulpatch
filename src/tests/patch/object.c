// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <errno.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <task/task.h>
#include <elf/elf-api.h>
#include <patch/patch.h>
#include <tests/test-api.h>


TEST(Patch_object, check, 0)
{
	int i, ret = 0;

	for (i = 0; i < nr_ulpatch_objs(); i++) {
		struct load_info info = {};
		char *obj = ulpatch_objs[i].path;
		char *tmpfile = "copy.obj";

		if (!fexist(obj)) {
			ret = -EEXIST;
			ulp_error("\n%s is not exist, maybe: make install\n", obj);
			break;
		}

		ret = alloc_patch_file(obj, tmpfile, &info);
		if (ret) {
			ulp_error("Parse %s failed.\n", obj);
			return ret;
		}

		setup_load_info(&info);

		/**
		 * Check patch info, see ULPATCH_INFO() macro
		 */
		if (info.ulp_info->version != ULPATCH_FILE_VERSION) {
			ulp_error("Wrong version %d, must be %d\n",
				info.ulp_info->version, ULPATCH_FILE_VERSION);
			ret++;
		}
		if (info.ulp_info->pad[0] != 0x11 || \
			info.ulp_info->pad[1] != 0x22 || \
			info.ulp_info->pad[2] != 0x33 || \
			info.ulp_info->pad[3] != 0x44) {
			ulp_error("Get wrong pad 0-3.\n");
			ret++;
		}

		release_load_info(&info);
		fremove(tmpfile);
	}

	return ret;
}
