#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#include <cli/cli_api.h>
#include <elf/elf_api.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>


static int cli_elf_ehdr_handler(const GElf_Ehdr *ehdr)
{
	return print_ehdr(ehdr);
}

static int __unused cli_elf_ehdr_handler_json(const GElf_Ehdr *ehdr)
{
	return print_json_ehdr(ehdr);
}

static int cli_elf_phdr_handler(const GElf_Phdr *phdr)
{
	return print_phdr(phdr);
}

static int __unused cli_elf_phdr_handler_json(const GElf_Phdr *phdr)
{
	return print_json_phdr(phdr);
}

static int cli_elf_shdr_handler(const GElf_Shdr *shdr, const char *secname)
{
	return print_shdr(shdr, secname);
}

static int cli_elf_shdr_handler_json(const GElf_Shdr *shdr, const char *secname)
{
	return print_json_shdr(shdr, secname);
}

static int cli_elf_syms_handler(const GElf_Sym *sym, const char *symname,
	const char *vername)
{
	return print_sym(sym, symname, vername);
}

static int cli_elf_syms_handler_json(const GElf_Sym *sym, const char *symname,
	const char *vername)
{
	return print_json_sym(sym, symname, vername);
}

int cli_cmd_get(const struct cli_struct *cli, int argc, char *argv[])
{
	if (argc < 2) {
		printf("help GET: to show help.\n");
	} else if (argc >= 2) {
		// GET ELF
		if (strcasecmp(argv[1], "elf") == 0) {
			// GET ELF XXX
			if (argc >= 3) {
				// GET ELF EHDR
				if (strcasecmp(argv[2], "ehdr") == 0) {
					if (argc == 4 && strcasecmp(argv[3], "json") == 0) {
						return client_get_elf_ehdr(cli->elf_client_fd,
								cli_elf_ehdr_handler_json);
					} else {
						return client_get_elf_ehdr(cli->elf_client_fd,
								cli_elf_ehdr_handler);
					}
				// GET ELF PHDR
				} else if (strcasecmp(argv[2], "phdr") == 0) {
					if (argc == 4 && strcasecmp(argv[3], "json") == 0) {
						return client_get_elf_phdr(cli->elf_client_fd,
								cli_elf_phdr_handler_json);
					} else {
						return client_get_elf_phdr(cli->elf_client_fd,
								cli_elf_phdr_handler);
					}
				// GET ELF SHDR
				} else if (strcasecmp(argv[2], "shdr") == 0) {
					if (argc == 4 && strcasecmp(argv[3], "json") == 0) {
						return client_get_elf_shdr(cli->elf_client_fd,
								cli_elf_shdr_handler_json);
					} else {
						return client_get_elf_shdr(cli->elf_client_fd,
								cli_elf_shdr_handler);
					}
				// GET ELF SYMS
				} else if (strcasecmp(argv[2], "syms") == 0) {
					if (argc == 4 && strcasecmp(argv[3], "json") == 0) {
						return client_get_elf_syms(cli->elf_client_fd,
								cli_elf_syms_handler_json);
					} else {
						return client_get_elf_syms(cli->elf_client_fd,
								cli_elf_syms_handler);
					}
				} else {
					printf("unknown %s argument.\n", argv[2]);
					return -ENOEXEC; /* Exec format error */
				}
			} else {
				printf("help GET ELF: to show help.\n");
				return -ENOEXEC; /* Exec format error */
			}
		}
	}

	return -ENOENT;
}

