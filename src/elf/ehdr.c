// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>

static bool check_ehdr_magic_is_ok(const GElf_Ehdr *ehdr)
{
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        return false;
    }
    return true;
}

const char *ei_class_string(const GElf_Ehdr *ehdr)
{
	switch (ehdr->e_ident[EI_CLASS]) {
	case ELFCLASSNONE: return "NONE";
	case ELFCLASS32: return "ELF32";
	case ELFCLASS64: return "ELF64";
	}
	return "Unknown";
}

const char *ei_data_string(const GElf_Ehdr *ehdr)
{
	switch (ehdr->e_ident[EI_DATA]) {
	case ELFDATANONE: return "Invalid data encoding";
	case ELFDATA2LSB: return "2's complement, little endian";
	case ELFDATA2MSB: return "2's complement, big endian";
	}
	return "Unknown";
}

const char *ei_osabi_string(const GElf_Ehdr *ehdr)
{
	switch (ehdr->e_ident[EI_OSABI]) {
	case ELFOSABI_SYSV: return "UNIX - System V";
	case ELFOSABI_HPUX: return "HP-UX";
	case ELFOSABI_NETBSD: return "NetBSD";
	case ELFOSABI_GNU: return "Object uses GNU ELF extensions";
	case ELFOSABI_SOLARIS: return "Sun Solaris";
	case ELFOSABI_AIX: return "IBM AIX";
	case ELFOSABI_IRIX: return "SGI Irix";
	case ELFOSABI_FREEBSD: return "FreeBSD";
	case ELFOSABI_TRU64: return "Compaq TRU64 UNIX";
	case ELFOSABI_MODESTO: return "Novell Modesto";
	case ELFOSABI_OPENBSD: return "OpenBSD";
	case ELFOSABI_ARM_AEABI: return "ARM EABI";
	case ELFOSABI_ARM: return "ARM";
	case ELFOSABI_STANDALONE: return "Standalone (embedded) application";
	}
	return "Unknown";
}

const char *e_type_string(const GElf_Ehdr *ehdr)
{
	switch (ehdr->e_type) {
	case ET_NONE: return "No file type";
	case ET_REL: return "Relocatable file";
	case ET_EXEC: return "Executable file";
	case ET_DYN: return "Shared object file";
	case ET_CORE: return "Core file";
	case ET_NUM: return "Number of defined types";
	case ET_LOOS: return "OS-specific range start";
	case ET_HIOS: return "OS-specific range end";
	case ET_LOPROC: return "Processor-specific range start";
	case ET_HIPROC: return "Processor-specific range end";
	}
	return "Unknown";
}

const char *e_machine_string(const GElf_Ehdr *ehdr)
{
	switch (ehdr->e_machine) {
	case EM_NONE: return "No machine type";
	case EM_ARM: return "arm";
	case EM_AARCH64: return "aarch64";
	case EM_X86_64: return "x86_64";
	default:
		return "Unknown";
	}
	return "Unknown";
}

int print_ehdr(const GElf_Ehdr *ehdr)
{
	int i;

	if (!check_ehdr_magic_is_ok(ehdr)) {
		return -EINVAL;
	}

	printf(
		"ELF Header:\n"
		" Magic:  "
	);
	for (i = 0; i < EI_NIDENT; i++) {
		uint8_t u8 = ehdr->e_ident[i];
		printf(" %02x", u8);
	} printf("\n");

	// see 'readelf -h|--file-header /usr/bin/ls' output
	printf(
		" Class:                             %s\n"
		" Data:                              %s\n"
		" Version:                           1 (current)\n" // Must be 1
		" OS/ABI:                            %s\n"
		" ABI Version:                       %d\n"
		" Type:                              %s\n"
		" Machine:                           %s\n"
		" Version:                           0x%x\n"
		" Entry point address:               0x%lx\n"
		" Start of program headers:          %ld (bytes into file)\n"
		" Start of section headers:          %ld (bytes into file)\n"
		" Flags:                             0x%x\n"
		" Size of this header:               %d (bytes)\n"
		" Size of program headers:           %d (bytes)\n"
		" Number of program headers:         %d\n"
		" Size of section headers:           %d (bytes)\n"
		" Number of section headers:         %d\n"
		" Section header string table index: %d\n",
		ei_class_string(ehdr),
		ei_data_string(ehdr),
		ei_osabi_string(ehdr),
		ehdr->e_ident[EI_ABIVERSION],
		e_type_string(ehdr),
		e_machine_string(ehdr),
		ehdr->e_version,
		ehdr->e_entry,
		ehdr->e_phoff,
		ehdr->e_shoff,
		ehdr->e_flags,
		ehdr->e_ehsize,
		ehdr->e_phentsize,
		ehdr->e_phnum,
		ehdr->e_shentsize,
		ehdr->e_shnum,
		ehdr->e_shstrndx
	);

	return 0;
}

#ifdef HAVE_JSON_C_LIBRARIES
json_object *json_ehdr(const GElf_Ehdr *ehdr)
{
	char buffer[256];
	if (!check_ehdr_magic_is_ok(ehdr)) {
		return NULL;
	}

	json_object *root = json_object_new_object();

	json_object *head = json_object_new_object();
	json_object *body = json_object_new_object();
	json_object *foot = json_object_new_object();

	json_object_object_add(root, "Head", head);
	json_object_object_add(root, "Body", body);
	json_object_object_add(root, "Foot", foot);

	/* Head */
	json_object_object_add(head,
		"Type", json_object_new_string("ELF Head"));

	/* Body */
	json_object_object_add(body,
		"Class", json_object_new_string(ei_class_string(ehdr)));

	json_object_object_add(body,
		"Data", json_object_new_string(ei_data_string(ehdr)));

	json_object_object_add(body,
		"Version", json_object_new_string("1 (current)"));

	json_object_object_add(body,
		"OS/ABI", json_object_new_string(ei_osabi_string(ehdr)));

	json_object_object_add(body,
		"ABI Version", json_object_new_int64(ehdr->e_ident[EI_ABIVERSION]));

	json_object_object_add(body,
		"Type", json_object_new_string(e_type_string(ehdr)));

	json_object_object_add(body,
		"Machine", json_object_new_string(e_machine_string(ehdr)));

	json_object_object_add(body,
		"Version_", json_object_new_int64(ehdr->e_version));

	snprintf(buffer, sizeof(buffer), "0x%lx", ehdr->e_entry);
	json_object_object_add(body,
		"Entry point address", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%ld (bytes into file)", ehdr->e_phoff);
	json_object_object_add(body,
		"Start of program headers", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%ld (bytes into file)", ehdr->e_shoff);
	json_object_object_add(body,
		"Start of section headers", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "0x%x", ehdr->e_flags);
	json_object_object_add(body,
		"Flags", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%d (bytes)", ehdr->e_ehsize);
	json_object_object_add(body,
		"Size of this header", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%d (bytes)", ehdr->e_phentsize);
	json_object_object_add(body,
		"Size of program headers", json_object_new_string(buffer));

	json_object_object_add(body,
		"Number of program headers", json_object_new_int64(ehdr->e_phnum));

	snprintf(buffer, sizeof(buffer), "%d (bytes)", ehdr->e_shentsize);
	json_object_object_add(body,
		"Size of section headers", json_object_new_string(buffer));

	json_object_object_add(body,
		"Number of section headers", json_object_new_int64(ehdr->e_shnum));

	json_object_object_add(body,
		"Section header string table index",
		json_object_new_int64(ehdr->e_shstrndx));

	/* Foot */
	json_object_object_add(foot,
		"Version", json_object_new_string(elftools_version()));

	return root;
}
#endif

int print_json_ehdr(const GElf_Ehdr *ehdr)
{
#ifdef HAVE_JSON_C_LIBRARIES
	json_object *root = json_ehdr(ehdr);
	if (!root) {
		return -EINVAL;
	}
	/* Print */
	printf("%s\r\n",
		json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));

	/* Free */
	json_object_put(root);

#else // HAVE_JSON_C_LIBRARIES

	lerror("Not support json-c.\n");
	return -EIO;
#endif

	return 0;
}

