#include <errno.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <elf/elf_api.h>

#include "../test_api.h"

// Initialized in other TEST_xxx()
extern int test_client_fd;

static const char *test_elfs[] = {
	"/usr/bin/at",
	"/usr/bin/attr",
	"/usr/bin/awk",
	"/usr/bin/bash",
	"/usr/bin/cat",
	"/usr/bin/grep",
	"/usr/bin/ls",
	"/usr/bin/mv",
	"/usr/bin/sed",
	"/usr/bin/w",
	"/usr/bin/wc",
	"/usr/bin/who",
};

static void print_elf(struct file_info *info)
{
	if (info->type == FILE_ELF)
		printf(" %s ELF %s\n", info->client_select?"> ":"  ", info->name);
}

static int register_handler(void) {
	return 0;
}
TEST(Elf_client,	client_register,	0)
{
	return client_register(test_client_fd, CLIENT_CLI, register_handler);
}

TEST(Elf_client,	open_delete,	0)
{
	int ret = -1;

	ret = client_open_elf_file(test_client_fd, "/usr/bin/ls");
	if (ret != 0) return ret;
	ret = client_delete_elf_file(test_client_fd, "/usr/bin/ls");
	if (ret != 0) return ret;

	return 0;
}

TEST(Elf_client,	open_twice,	0)
{
	int ret = -1;

	ret = client_open_elf_file(test_client_fd, "/usr/bin/ls");
	if (ret != 0) return ret;

	return client_open_elf_file(test_client_fd, "/usr/bin/ls");
}

TEST(Elf_client,	delete_twice,	-ENOENT)
{
	client_open_elf_file(test_client_fd, "/usr/bin/ls");
	client_delete_elf_file(test_client_fd, "/usr/bin/ls");

	return client_delete_elf_file(test_client_fd, "/usr/bin/ls");
}

TEST(Elf_client,	open_delete_loop,	0)
{
	int ret = -1, i;

	for (i = 0; i < ARRAY_SIZE(test_elfs); i++) {
		if (!fexist(test_elfs[i])) {
			continue;
		}
		ret = client_open_elf_file(test_client_fd, test_elfs[i]);
		if (ret != 0) break;
		ret = client_delete_elf_file(test_client_fd, test_elfs[i]);
		if (ret != 0) break;
	}

	return ret;
}

TEST(Elf_client,	list,	0)
{
	int ret = -1, i;

	for (i = 0; i < ARRAY_SIZE(test_elfs); i++) {
		if (!fexist(test_elfs[i])) {
			continue;
		}
		ret = client_open_elf_file(test_client_fd, test_elfs[i]);
		if (ret != 0) break;
		ret = client_list_elf(test_client_fd, print_elf);
		if (ret != 0) break;
		ret = client_delete_elf_file(test_client_fd, test_elfs[i]);
		if (ret != 0) break;
	}

	return ret;
}

TEST(Elf_client,	select,	0)
{
	int ret = -1, i;

	for (i = 0; i < ARRAY_SIZE(test_elfs); i++) {
		if (!fexist(test_elfs[i])) {
			continue;
		}
		ret = client_open_elf_file(test_client_fd, test_elfs[i]);
		if (ret != 0) break;
	}

	for (i = 0; i < ARRAY_SIZE(test_elfs); i++) {
		if (!fexist(test_elfs[i])) {
			continue;
		}
		ret = client_select_elf_file(test_client_fd, test_elfs[i]);
		if (ret != 0) break;
		client_list_elf(test_client_fd, print_elf);
	}

	for (i = 0; i < ARRAY_SIZE(test_elfs); i++) {
		if (!fexist(test_elfs[i])) {
			continue;
		}
		ret = client_delete_elf_file(test_client_fd, test_elfs[i]);
		if (ret != 0) break;
	}

	return ret;
}

static int get_ehdr_handler(const GElf_Ehdr *ehdr) { return print_ehdr(ehdr); }
TEST(Elf_client,	get_ehdr,	0)
{
	int ret;

	client_open_elf_file(test_client_fd, "/usr/bin/ls");
	client_select_elf_file(test_client_fd, "/usr/bin/ls");
	ret = client_get_elf_ehdr(test_client_fd, get_ehdr_handler);
	client_delete_elf_file(test_client_fd, "/usr/bin/ls");

	return ret;
}

TEST(Elf_client,	get_ehdr_non_exist,	-ENOENT)
{
	int ret;

	ret = client_get_elf_ehdr(test_client_fd, get_ehdr_handler);

	return ret;
}

static int get_ehdr_handler_json(const GElf_Ehdr *ehdr) {
	return print_json_ehdr(ehdr);
}
#ifdef HAVE_JSON_C_LIBRARIES
TEST(Elf_client,	get_ehdr_json,	0)
#else
TEST(Elf_client,	get_ehdr_json,	-EIO)
#endif //HAVE_JSON_C_LIBRARIES
{
	int ret;

	client_open_elf_file(test_client_fd, "/usr/bin/ls");
	client_select_elf_file(test_client_fd, "/usr/bin/ls");
	ret = client_get_elf_ehdr(test_client_fd, get_ehdr_handler_json);
	client_delete_elf_file(test_client_fd, "/usr/bin/ls");

	return ret;
}

static int get_phdr_handler(const GElf_Phdr *phdr) { return print_phdr(phdr); }
TEST(Elf_client,	get_phdr,	0)
{
	int ret;

	client_open_elf_file(test_client_fd, "/usr/bin/ls");
	client_select_elf_file(test_client_fd, "/usr/bin/ls");
	ret = client_get_elf_phdr(test_client_fd, get_phdr_handler);
	client_delete_elf_file(test_client_fd, "/usr/bin/ls");

	return ret;
}

TEST(Elf_client,	get_phdr_non_exist,	-ENOENT)
{
	int ret;

	ret = client_get_elf_phdr(test_client_fd, get_phdr_handler);

	return ret;
}

static int get_phdr_handler_json(const GElf_Phdr *phdr) {
	return print_json_phdr(phdr);
}
#ifdef HAVE_JSON_C_LIBRARIES
TEST(Elf_client,	get_phdr_json,	0)
#else
TEST(Elf_client,	get_phdr_json,	-EIO)
#endif //HAVE_JSON_C_LIBRARIES
{
	int ret;

	client_open_elf_file(test_client_fd, "/usr/bin/ls");
	client_select_elf_file(test_client_fd, "/usr/bin/ls");
	ret = client_get_elf_phdr(test_client_fd, get_phdr_handler_json);
	client_delete_elf_file(test_client_fd, "/usr/bin/ls");

	return ret;
}

static int get_shdr_handler(const GElf_Shdr *shdr, const char *secname) {
	return print_shdr(shdr, secname);
}
TEST(Elf_client,	get_shdr,	0)
{
	int ret;

	client_open_elf_file(test_client_fd, "/usr/bin/ls");
	client_select_elf_file(test_client_fd, "/usr/bin/ls");
	ret = client_get_elf_shdr(test_client_fd, get_shdr_handler);
	client_delete_elf_file(test_client_fd, "/usr/bin/ls");

	return ret;
}

TEST(Elf_client,	get_shdr_non_exist,	-ENOENT)
{
	return client_get_elf_shdr(test_client_fd, get_shdr_handler);
}

static int get_shdr_handler_json(const GElf_Shdr *shdr, const char *secname) {
	return print_json_shdr(shdr, secname);
}
#ifdef HAVE_JSON_C_LIBRARIES
TEST(Elf_client,	get_shdr_json,	0)
#else
TEST(Elf_client,	get_shdr_json,	-EIO)
#endif //HAVE_JSON_C_LIBRARIES
{
	int ret;

	client_open_elf_file(test_client_fd, "/usr/bin/ls");
	client_select_elf_file(test_client_fd, "/usr/bin/ls");
	ret = client_get_elf_shdr(test_client_fd, get_shdr_handler_json);
	client_delete_elf_file(test_client_fd, "/usr/bin/ls");

	return ret;
}

static int get_sym_handler(const GElf_Sym *sym, const char *symname,
	const char *vername) {
	return print_sym(sym, symname, vername);
}
TEST(Elf_client,	get_sym,	0)
{
	int ret;

	client_open_elf_file(test_client_fd, "/usr/bin/ls");
	client_select_elf_file(test_client_fd, "/usr/bin/ls");
	ret = client_get_elf_syms(test_client_fd, get_sym_handler);
	client_delete_elf_file(test_client_fd, "/usr/bin/ls");

	return ret;
}

TEST(Elf_client,	get_sym_non_exist,	-ENOENT)
{
	return client_get_elf_syms(test_client_fd, get_sym_handler);
}

static int get_sym_handler_json(const GElf_Sym *sym, const char *symname,
	const char *vername) {
	return print_json_sym(sym, symname, vername);
}
#ifdef HAVE_JSON_C_LIBRARIES
TEST(Elf_client,	get_sym_json,	0)
#else
TEST(Elf_client,	get_sym_json,	-EIO)
#endif //HAVE_JSON_C_LIBRARIES
{
	int ret;

	client_open_elf_file(test_client_fd, "/usr/bin/ls");
	client_select_elf_file(test_client_fd, "/usr/bin/ls");
	ret = client_get_elf_syms(test_client_fd, get_sym_handler_json);
	client_delete_elf_file(test_client_fd, "/usr/bin/ls");

	return ret;
}

