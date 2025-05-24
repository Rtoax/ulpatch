// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <sys/types.h>
#include <unistd.h>
#include <utils/log.h>
#include <utils/util.h>
#include <utils/list.h>
#include <utils/disasm.h>
#include <tests/test-api.h>


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
		int expect_errno;
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
		{
			.s = "0xff,0x1,0x3,0x2",
			.mem = {0xff,0x1,0x3,0x2},
			.n = 0,
			.seperator = ';', /* Bad string, return NULL */
			.expect_errno = EINVAL,
		},
	};

	ret = 0;

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		nbytes = 0;

		void *mem = strbytes2mem(values[i].s, &nbytes, buf, sizeof(buf),
				values[i].seperator);

		printf("%s : %ld (expect %ld)\n", values[i].s, nbytes, values[i].n);
#if defined(DEBUG)
		fdisasm_arch(stdout, ">> ", 0, (unsigned char *)mem, nbytes);
#endif
		if (nbytes != values[i].n) {
			ret++;
			continue;
		}

		/**
		 * errno equal to zero or EINVAL, and _MUST_ equal to
		 * expect_errno
		 */
		if (values[i].expect_errno != errno)
			ret++;

		if (!mem && errno != EINVAL)
			ret++;

		if (mem && memcmp(mem, values[i].mem, MAX(nbytes, values[i].n)))
			ret++;
	}

	return ret;
}

TEST(Utils_str, mem2strbytes, 0)
{
	int i, err = 0;
	char buf[1024];

	struct {
		uint8_t mem[128];
		size_t mem_len;
		char *expect_buf;
		size_t buf_len;
		char seperator;
		int expect_errno;
	} tests[] = {
		{
			.mem = {0x11},
			.mem_len = 1,
			.expect_buf = "0x11",
			.buf_len = 5,
			.seperator = ',',
		},
		{
			.mem = {0x1},
			.mem_len = 1,
			.expect_buf = "0x01",
			.buf_len = 5,
			.seperator = ',',
		},
		{
			.mem = {0x11},
			.mem_len = 1,
			.expect_buf = "0x11",
			.buf_len = 4,
			.seperator = ',',
			.expect_errno = EINVAL,
		},
		{
			.mem = {0x11,0x22},
			.mem_len = 2,
			.expect_buf = "0x11,0x22",
			.buf_len = 10,
			.seperator = ',',
		},
		{
			.mem = {0x1,0xf},
			.mem_len = 2,
			.expect_buf = "0x01,0x0f",
			.buf_len = 10,
			.seperator = ',',
		},
		{
			.mem = {0x11,0x22},
			.mem_len = 2,
			.expect_buf = "0x11#0x22",
			.buf_len = 10,
			.seperator = '#',
		},
		{
			.mem = {0x11,0x22,0x33,0x44,0x55,0x66,0x77},
			.mem_len = 7,
			.expect_buf = "0x11,0x22,0x33,0x44,0x55,0x66,0x77",
			.buf_len = 35,
			.seperator = ',',
		},
	};

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		char *s = mem2strbytes(tests[i].mem, tests[i].mem_len, buf,
				       tests[i].buf_len, tests[i].seperator);

		if (errno == 0 && !s)
			err++;

		if (tests[i].expect_errno != errno)
			err++;

		if (s && strcmp(buf, tests[i].expect_buf))
			err++;

		printf("s = <%s> (%s) err = %d\n", s, tests[i].expect_buf, err);
	}

	return err;
}

TEST(Utils_str, strbytes2mem2strbytes, 0)
{
	int i, err = 0;
	size_t nbytes;
	char mem_buf[1024];
	char str_buf[1024];

	struct {
		char *from_str;
		size_t nbytes;
		char seperator;
		char *to_str;
	} tests[] = {
		{
			.from_str = "0x1",
			.nbytes = 1,
			.seperator = ',',
			.to_str = "0x01",
		},
		{
			.from_str = "0x1,0x2",
			.nbytes = 2,
			.seperator = ',',
			.to_str = "0x01,0x02",
		},
		{
			.from_str = "0x1#0x2#0x03",
			.nbytes = 3,
			.seperator = '#',
			.to_str = "0x01#0x02#0x03",
		},
		{
			.from_str = "0x1,0x2,0x3,0x4,0x5,0x6",
			.nbytes = 6,
			.seperator = ',',
			.to_str = "0x01,0x02,0x03,0x04,0x05,0x06",
		},
	};

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		void *mem = strbytes2mem(tests[i].from_str, &nbytes, mem_buf,
					 sizeof(mem_buf),
					 tests[i].seperator);
		char *s = mem2strbytes(mem, tests[i].nbytes, str_buf,
				       sizeof(str_buf), tests[i].seperator);

		if (strcmp(s, tests[i].to_str))
			err++;

		printf("s = <%s> (%s)\n", s, tests[i].to_str);
	}

	return err;
}

TEST(Utils_str, strprintbuf, 0)
{
	int err = 0;
	char buf[1024];
	err += strcmp("", strprintbuf(buf, sizeof(buf), ""));
	err += strcmp("hello", strprintbuf(buf, sizeof(buf), "hello"));
	err += strcmp("hello world", strprintbuf(buf, sizeof(buf), "hello %s", "world"));
	err += strcmp("1234", strprintbuf(buf, sizeof(buf), "%d%d%d%d", 1, 2, 3, 4));
	return err;
}
