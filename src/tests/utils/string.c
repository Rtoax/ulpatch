// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <sys/types.h>
#include <unistd.h>
#include <utils/log.h>
#include <utils/util.h>
#include <utils/list.h>
#include <utils/disasm.h>
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

TEST(Utils_str, fmembytes, 0)
{
	return fmembytes(stdout, docs, sizeof(docs));
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
		{"01234", 01234},
		{"001234", 01234},
	};

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		unsigned long v = str2addr(values[i].str);
		ulp_debug("v = 0x%lx, %ld\n", v, v);
		if (v != values[i].expect)
			ret++;
	}

	return ret;
}

TEST(Utils_str, strbytes2mem, 0)
{
	int ret, i;
	char buf[1024];
	size_t nbytes;

	struct {
		char *s;
		uint8_t mem[128];
		size_t n;
		char seperator;
	} values[] = {
		{
			.s = "0xff",
			.mem = {0xff},
			.n = 1,
		},
		{
			.s = "0xff,",
			.mem = {0xff},
			.n = 1,
		},
		{
			.s = ",,,0xff,,,,",
			.mem = {0xff},
			.n = 1,
		},
		{
			.s = "0xff,0x11",
			.mem = {0xff,0x11},
			.n = 2,
		},
		{
			.s = ",,,,0xff,,,0x11,,,",
			.mem = {0xff,0x11},
			.n = 2,
		},
		{
			.s = "0xff,0x1,0x2",
			.mem = {0xff,0x1,0x2},
			.n = 3,
		},
		{
			.s = "0xff,,,0x1,,,0x2,,",
			.mem = {0xff,0x1,0x2},
			.n = 3,
		},
		{
			.s = "0xff,0x25,0x02,0x00,0x00,0x00,0x90,0x90",
			.mem = {0xff,0x25,0x02,0x00,0x00,0x00,0x90,0x90},
			.n = 8,
		},
		{
			.s = "0xff,0x25,0x02,0x00,0x00,0x00,0x90,0x90,0xff,0x25,0x02,0x00,0x00",
			.mem = {0xff,0x25,0x02,0x00,0x00,0x00,0x90,0x90,0xff,0x25,0x02,0x00,0x00},
			.n = 13,
		},
		{
			.s = "0xff,0x25,0x02,0x00,0x00,0x00,0x90,0x90,0xff,0x25,0x02,0x00,0x00,0x00,0x90,0x90",
			.mem = {0xff,0x25,0x02,0x00,0x00,0x00,0x90,0x90,0xff,0x25,0x02,0x00,0x00,0x00,0x90,0x90},
			.n = 16,
		},
		{
			.s = "0xff;",
			.mem = {0xff},
			.n = 1,
			.seperator = ';',
		},
		{
			.s = "+++0xff+++0x1++++0x3++0x2++",
			.mem = {0xff,0x1,0x3,0x2},
			.n = 4,
			.seperator = '+',
		},
	};

	ret = 0;

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		void *mem = strbytes2mem(values[i].s, &nbytes, buf, sizeof(buf),
				values[i].seperator);

		printf("%s : %ld (expect %ld)\n", values[i].s, nbytes, values[i].n);
#if defined(DEBUG)
		fdisasm_arch(stdout, ">> ", 0, (unsigned char *)mem, nbytes);
#endif
		if (memcmp(mem, values[i].mem, MAX(nbytes, values[i].n)))
			ret++;

		if (nbytes != values[i].n)
			ret++;
	}

	return ret;
}
