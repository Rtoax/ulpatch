// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <utils/list.h>

#ifdef __cplusplus
extern "C" {
#endif

struct command_help {
	char *name;
	char *params;
	char *summary;
};

struct help_entry {
	int argc;
	char **argv;
	char *full;

	struct list_head node;

	struct command_help help;
};

struct command_help commands_help[] = {
	{
		.name = "LOAD",
		.params = "",
		.summary = "Load a type file, etc.",
	},
	{
		.name = "LOAD ELF",
		.params = "[filepath]",
		.summary = "Load a ELF file",
	},
	{
		.name = "DELETE",
		.params = "",
		.summary = "Delete a type file, etc.",
	},
	{
		.name = "DELETE ELF",
		.params = "[filepath]",
		.summary = "Delete a ELF file",
	},
	{
		.name = "LIST",
		.params = "",
		.summary = "List a type of list",
	},
	{
		.name = "LIST ELF",
		.params = "",
		.summary = "List loaded ELF file",
	},
	{
		.name = "LIST CLIENT",
		.params = "",
		.summary = "List all connected Clients",
	},
	{
		.name = "SELECT",
		.params = "",
		.summary = "Select something",
	},
	{
		.name = "SELECT ELF",
		.params = "[filepath]",
		.summary = "Select loaded ELF file",
	},
	{
		.name = "GET",
		.params = "",
		.summary = "Get something",
	},
	{
		.name = "GET ELF",
		.params = "",
		.summary = "Get ELF",
	},
	{
		.name = "GET ELF EHDR",
#ifdef HAVE_JSON_C_LIBRARIES
		.params = "[json]",
#else
		.params = "",
#endif
		.summary = "Get ELF Ehdr",
	},
	{
		.name = "GET ELF PHDR",
#ifdef HAVE_JSON_C_LIBRARIES
		.params = "[json]",
#else
		.params = "",
#endif
		.summary = "Get ELF Phdr",
	},
	{
		.name = "GET ELF SHDR",
#ifdef HAVE_JSON_C_LIBRARIES
		.params = "[json]",
#else
		.params = "",
#endif
		.summary = "Get ELF Shdr",
	},
	{
		.name = "GET ELF SYMS",
#ifdef HAVE_JSON_C_LIBRARIES
		.params = "[json]",
#else
		.params = "",
#endif
		.summary = "Get ELF Symbols",
	},
	{
		.name = "SHELL",
		.params = "<command> [arg1] ...",
		.summary = "Execute command on client",
	},
	{
		.name = "TEST",
		.params = "",
		.summary = "TEST something",
	},
	{
		.name = "TEST SERVER",
		.params = "",
		.summary = "TEST the UNIX socket",
	},
};

#ifdef __cplusplus
}
#endif

