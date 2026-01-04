// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>

#include "elf/elf-api.h"
#include "utils/utils.h"
#include "utils/log.h"


bool ehdr_magic_ok(const GElf_Ehdr *ehdr)
{
	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3) {
		ulp_debug("Wrong ELF magic\n");
		return false;
	}
	return true;
}

bool ehdr_ok(const GElf_Ehdr *ehdr)
{
	if (ehdr->e_type == ET_NONE) {
		ulp_debug("unknown elf type %d\n", ehdr->e_type);
		goto not_ok;
	}
	if (ehdr->e_machine == EM_NONE) {
		ulp_debug("unknown elf machine %d\n", ehdr->e_machine);
		goto not_ok;
	}
	if (ehdr->e_version != EV_CURRENT) {
		ulp_debug("unknown elf version %d\n", ehdr->e_version);
		goto not_ok;
	}
	/* Only support 64bit system */
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		ulp_debug("unsupport %d\n", ehdr->e_ident[EI_CLASS]);
		goto not_ok;
	}
	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
		ulp_debug("unsupport %d\n", ehdr->e_ident[EI_DATA]);
		goto not_ok;
	}
	if (!ehdr_magic_ok(ehdr)) {
		goto not_ok;
	}

	return true;
not_ok:
	return false;
}

static const char *ei_class_string(const GElf_Ehdr *ehdr)
{
	switch (ehdr->e_ident[EI_CLASS]) {
	case ELFCLASSNONE: return "NONE";
	case ELFCLASS32: return "ELF32";
	case ELFCLASS64: return "ELF64";
	}
	return "Unknown";
}

static const char *ei_data_string(const GElf_Ehdr *ehdr)
{
	switch (ehdr->e_ident[EI_DATA]) {
	case ELFDATANONE: return "Invalid data encoding";
	case ELFDATA2LSB: return "2's complement, little endian";
	case ELFDATA2MSB: return "2's complement, big endian";
	}
	return "Unknown";
}

static const char *ei_osabi_string(const GElf_Ehdr *ehdr)
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

static const char *e_type_string(const GElf_Ehdr *ehdr)
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

static const char *e_machine_string(const GElf_Ehdr *ehdr)
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

int print_ehdr(FILE *fp, const GElf_Ehdr *ehdr)
{
	int i;

	if (!ehdr || !ehdr_magic_ok(ehdr)) {
		ulp_error("Print unknown pointer as elf header.\n");
		return -EINVAL;
	}

	fp = fp ?: stdout;

	fprintf(fp,
		"ELF Header:\n"
		" Magic:  ");
	for (i = 0; i < EI_NIDENT; i++) {
		uint8_t u8 = ehdr->e_ident[i];
		fprintf(fp, " %02x", u8);
	} fprintf(fp, "\n");

	fprintf(fp,
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

