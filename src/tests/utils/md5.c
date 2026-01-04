// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025-2026 Rong Tao */
#include "utils/log.h"
#include "utils/list.h"
#include "utils/utils.h"

#include "tests/test-api.h"


TEST(Utils_md5, fmd5sum, 0)
{
	int err = 0;
	char *file = "/etc/os-release";
	unsigned char md5_result[EVP_MAX_MD_SIZE];

	err = fmd5sum(file, md5_result);
	if (err == 0) {
		printf("MD5 hash of file %s: ", file);
		for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
			printf("%02x", md5_result[i]);
		}
		printf("\n");
	}
	return err;
}
