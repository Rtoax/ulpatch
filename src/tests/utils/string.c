// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <sys/types.h>
#include <unistd.h>
#include <utils/log.h>
#include <utils/list.h>
#include <tests/test-api.h>

TEST_STUB(utils_string);

static char docs[] = {
	"This is a memshow() test.\n"
	"	"
	"\n"
	" Never give up, Never lose hope.\n"
	" Always have faith, It allows you to cope.\n"
	" Trying times will pass, As they always do.\n"
	" Just have patience, Your dreams will come true.\n"
	" So put on a smile, You'll live through your pain.\n"
	" Know it will pass, And strength you will gain.\n"
	"\n"
};

TEST(Utils_str, memshow, 0)
{
#define TEST_DATA	"Hello World"
	memshowinlog(LOG_INFO, TEST_DATA, sizeof(TEST_DATA));

	memshow(get_log_fp(), docs, sizeof(docs));

	/* print nothing */
	memshow(NULL, docs, sizeof(docs));

	return 0;
}

TEST(Utils_str, print, 0)
{
	print_string_hex(stdout, NULL, (void *)docs, sizeof(docs));
	print_bytes(stdout, docs, sizeof(docs));
	return 0;
}

TEST(Utils_str, str2size, 0)
{
	int i, ret = 0;

	struct {
		char *str;
		unsigned long expect;
	} values[] = {
		{"0x1234", 0x1234},
		{"1234", 1234},
		{"0x1234KB", 0x1234 * KB},
		{"1234KB", 1234 * KB},
		{"1234MB", 1234 * MB},
		{"1234GB", 1234 * GB},
	};

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		unsigned long v = str2size(values[i].str);
		ulp_debug("v = %lx\n", v);
		if (v != values[i].expect)
			ret++;
	}

	return ret;
}

TEST(Utils_str, str2addr, 0)
{
	int i, ret = 0;

	struct {
		char *str;
		unsigned long expect;
	} values[] = {
		{"0x1234", 0x1234},
		{"1234", 1234},
		{"0x1234KB", 0x1234},
		{"1234KB", 1234},
	};

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		unsigned long v = str2addr(values[i].str);
		ulp_debug("v = %lx\n", v);
		if (v != values[i].expect)
			ret++;
	}

	return ret;
}
