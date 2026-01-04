// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025-2026 Rong Tao */
#include <stdarg.h>
#include <libgen.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

#include "utils/log.h"

#include "utils/compiler.h"
#include "utils/file.h"


/* Function: Calculate the MD5 hash of a file using OpenSSL's EVP API */
int fmd5sum(const char *filename, unsigned char *md5_result)
{
	FILE *file = fopen(filename, "rb");
	if (!file) {
		ulp_error("Unable to open file");
		return -errno;
	}

	/* Create a new EVP_MD_CTX */
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
	if (!md_ctx) {
		ulp_error("Failed to create EVP_MD_CTX");
		fclose(file);
		return -1;
	}

	/* Get the MD5 digest method */
	const EVP_MD *md5 = EVP_md5();
	if (EVP_DigestInit_ex(md_ctx, md5, NULL) != 1) {
		ulp_error("EVP_DigestInit_ex failed");
		EVP_MD_CTX_free(md_ctx);
		fclose(file);
		return -1;
	}

	unsigned char buffer[1024];
	size_t bytes_read;

	while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
		if (EVP_DigestUpdate(md_ctx, buffer, bytes_read) != 1) {
			ulp_error("EVP_DigestUpdate failed");
			EVP_MD_CTX_free(md_ctx);
			fclose(file);
			return -1;
		}
	}

	if (ferror(file)) {
		ulp_error("Error reading file");
		EVP_MD_CTX_free(md_ctx);
		fclose(file);
		return -1;
	}

	if (EVP_DigestFinal_ex(md_ctx, md5_result, NULL) != 1) {
		ulp_error("EVP_DigestFinal_ex failed");
		EVP_MD_CTX_free(md_ctx);
		fclose(file);
		return -1;
	}

	EVP_MD_CTX_free(md_ctx);
	fclose(file);

	return 0;
}
