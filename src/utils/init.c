// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "log.h"
#include "compiler.h"


void ulpatch_env_init(void)
{
	if (!fexist("/tmp")) {
		fprintf(stderr, "Need /tmp/\n");
		exit(1);
	}

	if (!fexist(ROOT_DIR)) {
		if (mkdirat(0, ROOT_DIR, 0755) != 0) {
			fprintf(stderr, "Create %s failed, %s\n",
				ROOT_DIR, strerror(errno));
			exit(1);
		}
	}
}

