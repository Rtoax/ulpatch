// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <sys/types.h>
#include <unistd.h>
#include <utils/log.h>
#include <utils/list.h>
#include <tests/test_api.h>


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

TEST(Utils, memshow, 0)
{

#define TEST_DATA	"Hello World"
	memshowinlog(LOG_INFO, TEST_DATA, sizeof(TEST_DATA));

	memshow(get_log_fp(), docs, sizeof(docs));

	/* print nothing */
	memshow(NULL, docs, sizeof(docs));

	return 0;
}

