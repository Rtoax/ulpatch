#include <errno.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <elf/elf_api.h>
#include <cli/cli_api.h>

#include "../test_api.h"

// Initialized in other TEST_xxx()
extern int test_client_fd;


TEST(Cli_cmd,	elf_load,	0)
{
	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 3;
	char *argv[] = {
		"LOAD",
		"ELF",
		"/usr/bin/ls",
		NULL
	};
	return cli_cmd_load(&cli, argc, argv);
}

TEST(Cli_cmd,	elf_delete,	0)
{
	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 3;
	char *argv[] = {
		"DELETE",
		"ELF",
		"/usr/bin/ls",
		NULL
	};
	return cli_cmd_delete(&cli, argc, argv);
}

TEST(Cli_cmd,	elf_list,	0)
{
	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 2;
	char *argv[] = {
		"LIST",
		"ELF",
		NULL
	};
	return cli_cmd_list(&cli, argc, argv);
}

TEST(Cli_cmd,	list_client,	0)
{
	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 2;
	char *argv[] = {
		"LIST",
		"CLIENT",
		NULL
	};
	return cli_cmd_list(&cli, argc, argv);
}

TEST(Cli_cmd,	elf_select,	0)
{
	int ret;
#define TEST_FILE "/usr/bin/ls"

	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 3;
	char *argv[] = {
		"SELECT",
		"ELF",
		TEST_FILE,
		NULL
	};

	client_open_elf_file(cli.elf_client_fd, TEST_FILE);

	ret = cli_cmd_select(&cli, argc, argv);

	client_delete_elf_file(cli.elf_client_fd, TEST_FILE);

#undef TEST_FILE

	return ret;
}

TEST(Cli_cmd,	elf_get_ehdr,	0)
{
	int ret;
#define TEST_FILE "/usr/bin/ls"

	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 3;
	char *argv[] = {
		"GET",
		"ELF",
		"EHDR",
		NULL
	};

	client_open_elf_file(cli.elf_client_fd, TEST_FILE);
	client_select_elf_file(cli.elf_client_fd, TEST_FILE);

	ret = cli_cmd_get(&cli, argc, argv);

	client_delete_elf_file(cli.elf_client_fd, TEST_FILE);

#undef TEST_FILE

	return ret;
}

#ifdef HAVE_JSON_C_LIBRARIES
TEST(Cli_cmd,	elf_get_ehdr_json,	0)
#else
TEST(Cli_cmd,	elf_get_ehdr_json,	-EIO)
#endif
{
	int ret;
#define TEST_FILE "/usr/bin/ls"

	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 4;
	char *argv[] = {
		"GET",
		"ELF",
		"EHDR",
		"json",
		NULL
	};

	client_open_elf_file(cli.elf_client_fd, TEST_FILE);
	client_select_elf_file(cli.elf_client_fd, TEST_FILE);

	ret = cli_cmd_get(&cli, argc, argv);

	client_delete_elf_file(cli.elf_client_fd, TEST_FILE);

#undef TEST_FILE

	return ret;
}

TEST(Cli_cmd,	elf_get_phdr,	0)
{
	int ret;
#define TEST_FILE "/usr/bin/ls"

	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 3;
	char *argv[] = {
		"GET",
		"ELF",
		"PHDR",
		NULL
	};

	client_open_elf_file(cli.elf_client_fd, TEST_FILE);
	client_select_elf_file(cli.elf_client_fd, TEST_FILE);

	ret = cli_cmd_get(&cli, argc, argv);

	client_delete_elf_file(cli.elf_client_fd, TEST_FILE);

#undef TEST_FILE

	return ret;
}

#ifdef HAVE_JSON_C_LIBRARIES
TEST(Cli_cmd,	elf_get_phdr_json,	0)
#else
TEST(Cli_cmd,	elf_get_phdr_json,	-EIO)
#endif
{
	int ret;
#define TEST_FILE "/usr/bin/ls"

	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 4;
	char *argv[] = {
		"GET",
		"ELF",
		"PHDR",
		"json",
		NULL
	};

	client_open_elf_file(cli.elf_client_fd, TEST_FILE);
	client_select_elf_file(cli.elf_client_fd, TEST_FILE);

	ret = cli_cmd_get(&cli, argc, argv);

	client_delete_elf_file(cli.elf_client_fd, TEST_FILE);

#undef TEST_FILE

	return ret;
}

TEST(Cli_cmd,	elf_get_shdr,	0)
{
	int ret;
#define TEST_FILE "/usr/bin/ls"

	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 3;
	char *argv[] = {
		"GET",
		"ELF",
		"SHDR",
		NULL
	};

	client_open_elf_file(cli.elf_client_fd, TEST_FILE);
	client_select_elf_file(cli.elf_client_fd, TEST_FILE);

	ret = cli_cmd_get(&cli, argc, argv);

	client_delete_elf_file(cli.elf_client_fd, TEST_FILE);

#undef TEST_FILE

	return ret;
}


#ifdef HAVE_JSON_C_LIBRARIES
TEST(Cli_cmd,	elf_get_shdr_json,	0)
#else
TEST(Cli_cmd,	elf_get_shdr_json,	-EIO)
#endif
{
	int ret;
#define TEST_FILE "/usr/bin/ls"

	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 4;
	char *argv[] = {
		"GET",
		"ELF",
		"SHDR",
		"json",
		NULL
	};

	client_open_elf_file(cli.elf_client_fd, TEST_FILE);
	client_select_elf_file(cli.elf_client_fd, TEST_FILE);

	ret = cli_cmd_get(&cli, argc, argv);

	client_delete_elf_file(cli.elf_client_fd, TEST_FILE);

#undef TEST_FILE

	return ret;
}

TEST(Cli_cmd,	elf_get_syms,	0)
{
	int ret;
#define TEST_FILE "/usr/bin/ls"

	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 3;
	char *argv[] = {
		"GET",
		"ELF",
		"SYMS",
		NULL
	};

	client_open_elf_file(cli.elf_client_fd, TEST_FILE);
	client_select_elf_file(cli.elf_client_fd, TEST_FILE);

	ret = cli_cmd_get(&cli, argc, argv);

	client_delete_elf_file(cli.elf_client_fd, TEST_FILE);

#undef TEST_FILE

	return ret;
}


#ifdef HAVE_JSON_C_LIBRARIES
TEST(Cli_cmd,	elf_get_syms_json,	0)
#else
TEST(Cli_cmd,	elf_get_syms_json,	-EIO)
#endif
{
	int ret;
#define TEST_FILE "/usr/bin/ls"

	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 4;
	char *argv[] = {
		"GET",
		"ELF",
		"SYMS",
		"json",
		NULL
	};

	client_open_elf_file(cli.elf_client_fd, TEST_FILE);
	client_select_elf_file(cli.elf_client_fd, TEST_FILE);

	ret = cli_cmd_get(&cli, argc, argv);

	client_delete_elf_file(cli.elf_client_fd, TEST_FILE);

#undef TEST_FILE

	return ret;
}

TEST(Cli_cmd,	test_server,	0)
{
	struct cli_struct cli = {
		.elf_client_fd = test_client_fd
	};
	int argc = 2;
	char *argv[] = {
		"TEST",
		"SERVER",
		NULL
	};

	return cli_cmd_test(&cli, argc, argv);
}

TEST(Cli_cmd,	shell_ls,	0)
{
	int argc = 2;
	char *argv[] = {
		"SHELL",
		"ls",
		NULL
	};

	return cli_cmd_shell(argc, argv);
}

TEST(Cli_cmd,	shell_cat_os_release,	0)
{
	int argc = 3;
	char *argv[] = {
		"SHELL",
		"cat",
		"/etc/os-release",
		NULL
	};

	return cli_cmd_shell(argc, argv);
}

