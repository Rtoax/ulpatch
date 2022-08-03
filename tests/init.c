// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <utils/log.h>
#include <utils/list.h>
#include <elf/elf_api.h>

#include "test_api.h"

int test_client_fd = -1;

TEST_HIGHEST(Elf_init,	elf_main,	0)
{
	int argc = 0;
	char **argv = NULL;

	return elf_main(argc, argv);
}

TEST_HIGHEST(Elf_init,	create_elf_client,	0)
{
	if (test_client_fd > 0) {
		fprintf(stderr, "already created.\n");
		return -1;
	}
	test_client_fd = create_elf_client();
	return test_client_fd>0?0:-1;
}

TEST_HIGHEST(Elf_init,	close_elf_client,	0)
{
	int ret = -1;

	if (test_client_fd <= 0) {
		test_client_fd = create_elf_client();
		if (test_client_fd <= 0) {
			return -1;
		}
	}
	ret = close_elf_client(test_client_fd);

	test_client_fd = -1;
	return ret;
}

// Need create fd again for the following tests
TEST_HIGHEST(Elf_init,	create_elf_client_again,	0)
{
	if (test_client_fd <= 0) {
		test_client_fd = create_elf_client();
	}
	return test_client_fd>0?0:-1;
}

TEST_LOWER(Elf_init,	elf_exit,	0)
{
	elf_exit();
	return 0;
}

