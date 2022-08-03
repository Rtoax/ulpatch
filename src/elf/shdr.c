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


const char *sh_name_string(const GElf_Shdr *shdr)
{
	switch (shdr->sh_name) {
	case SHN_UNDEF: return "Undefined section";
	case SHN_LORESERVE: return "Start of reserved indices";
//	case SHN_LOPROC: return "Start of processor-specific";
//	case SHN_BEFORE: return "Order section before all others (Solaris)";
	case SHN_AFTER: return "Order section after all others (Solaris)";
	case SHN_HIPROC: return "End of processor-specific";
	case SHN_LOOS: return "Start of OS-specific";
	case SHN_HIOS: return "End of OS-specific";
	case SHN_ABS: return "Associated symbol is absolute";
	case SHN_COMMON: return "Associated symbol is common";
	case SHN_XINDEX: return "Index is in extra table";
//	case SHN_HIRESERVE: return "End of reserved indices";
	}
	return "unknown";
}

const char *sh_type_string(const GElf_Shdr *shdr)
{
	switch (shdr->sh_type) {
	case SHT_NULL: return "Section header table entry unused";
	case SHT_PROGBITS: return "Program data";
	case SHT_SYMTAB: return "Symbol table";
	case SHT_STRTAB: return "String table";
	case SHT_RELA: return "Relocation entries with addends";
	case SHT_HASH: return "Symbol hash table";
	case SHT_DYNAMIC: return "Dynamic linking information";
	case SHT_NOTE: return "Notes";
	case SHT_NOBITS: return "Program space with no data";
	case SHT_REL: return "Relocation entries, no addends";
	case SHT_SHLIB: return "Reserved";
	case SHT_DYNSYM: return "Dynamic linker symbol table";
	case SHT_INIT_ARRAY: return "Array of constructors ";
	case SHT_FINI_ARRAY: return "Array of destructors";
	case SHT_PREINIT_ARRAY: return "Array of pre-constructors";
	case SHT_GROUP: return "Section group";
	case SHT_SYMTAB_SHNDX: return "Extended section indices";
	case SHT_NUM: return "Number of defined types.";
	case SHT_LOOS: return "Start OS-specific.";
	case SHT_GNU_ATTRIBUTES: return "Object attributes.";
	case SHT_GNU_HASH: return "GNU-style hash table.";
	case SHT_GNU_LIBLIST: return "Prelink library list";
	case SHT_CHECKSUM: return "Checksum for DSO content.";
	//case SHT_LOSUNW: return "Sun-specific low bound.  ";
	case SHT_SUNW_move: return "SHT_SUNW_move";
	case SHT_SUNW_COMDAT: return "SHT_SUNW_COMDAT";
	case SHT_SUNW_syminfo: return "SHT_SUNW_syminfo";
	case SHT_GNU_verdef: return "Version definition section.";
	case SHT_GNU_verneed: return "Version needs section.";
	case SHT_GNU_versym: return "Version symbol table.";
	//case SHT_HISUNW: return "Sun-specific high bound.";
	//case SHT_HIOS: return "End OS-specific type";
	case SHT_LOPROC: return "Start of processor-specific";
	case SHT_HIPROC: return "End of processor-specific";
	case SHT_LOUSER: return "Start of application-specific";
	case SHT_HIUSER: return "End of application-specific";
	}
	return "Unknown";
}

const char *sh_flags_string(const GElf_Shdr *shdr, void *buff, ssize_t buff_len)
{
	int idx = 0;
	char *flags = (char*)buff;

	if (!flags || buff_len < 33) {
		lerror("buffer invalied.\n");
		return NULL;
	}

	memset(flags, 0x0, sizeof(char)*32);

	/**
	 * Key to Flags:
	 * W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
	 * L (link order), O (extra OS processing required), G (group), T (TLS),
	 * C (compressed), x (unknown), o (OS specific), E (exclude),
	 * l (large), p (processor specific)
	 */
	/* Writable */
	if (shdr->sh_flags & SHF_WRITE)
		flags[idx++] = 'W';
	/* Occupies memory during execution */
	if (shdr->sh_flags & SHF_ALLOC)
		flags[idx++] = 'A';
	/* Executable */
	if (shdr->sh_flags & SHF_EXECINSTR)
		flags[idx++] = 'X';
	/* Might be merged */
	if (shdr->sh_flags & SHF_MERGE)
		flags[idx++] = 'M';
	/* Contains nul-terminated strings */
	if (shdr->sh_flags & SHF_STRINGS)
		flags[idx++] = 'S';
	/* `sh_info' contains SHT index */
	if (shdr->sh_flags & SHF_INFO_LINK)
		flags[idx++] = 'I';
	/* Preserve order after combining */
	if (shdr->sh_flags & SHF_LINK_ORDER)
		flags[idx++] = 'L';
	/* Non-standard OS specific handling required */
	if (shdr->sh_flags & SHF_OS_NONCONFORMING)
		flags[idx++] = 'O';
	/* Section is member of a group.  */
	if (shdr->sh_flags & SHF_GROUP)
		flags[idx++] = 'G';
	/* Section hold thread-local data.  */
	if (shdr->sh_flags & SHF_TLS)
		flags[idx++] = 'T';
	/* Section with compressed data. */
	if (shdr->sh_flags & SHF_COMPRESSED)
		flags[idx++] = 'C';
	/* OS-specific.  */
	if (shdr->sh_flags & SHF_MASKOS) {
		//TODO
	}
	/* Processor-specific */
	if (shdr->sh_flags & SHF_MASKPROC) {
		//TODO
	}
#ifdef SHF_GNU_RETAIN
	/* Not to be GCed by linker.  */
	if (shdr->sh_flags & SHF_GNU_RETAIN)
		flags[idx++] = 'g';
#endif
	/* Special ordering requirement(Solaris).  */
	if (shdr->sh_flags & SHF_ORDERED)
		flags[idx++] = 'o';
	/* Section is excluded unless referenced or allocated (Solaris).*/
	if (shdr->sh_flags & SHF_EXCLUDE)
		flags[idx++] = 'E';

	flags[idx] = '\0';

	return flags;
}

// see readelf -S|--section-headers|--sections
int print_shdr(const GElf_Shdr *shdr, const char *secname)
{
	char buffer[64];

	printf(
		"\033[7m"
		" Name               Type              Address            Offset"
		"\033[m\n"
		" %-18s %-17s %#016lx %#08lx\n"
		" Size               EntSize           Flags  Link  Info  Align\n"
		" %#018lx %#017lx %-4s %4d %4d %8ld\n",
		secname,
		sh_type_string(shdr),
		shdr->sh_addr,
		shdr->sh_offset,
		shdr->sh_size,
		shdr->sh_entsize,
		sh_flags_string(shdr, buffer, sizeof(buffer)),
		shdr->sh_link,
		shdr->sh_info,
		shdr->sh_addralign
	);

	return 0;
}

#ifdef HAVE_JSON_C_LIBRARIES
json_object *json_shdr(const GElf_Shdr *shdr, const char *secname)
{
	char __unused buffer[256];

	json_object *root = json_object_new_object();

	json_object *head = json_object_new_object();
	json_object *body = json_object_new_object();
	json_object *foot = json_object_new_object();

	json_object_object_add(root, "Head", head);
	json_object_object_add(root, "Body", body);
	json_object_object_add(root, "Foot", foot);

	/* Head */
	json_object_object_add(head,
		"Type", json_object_new_string("ELF Section Head"));

	/* Body */
	json_object_object_add(body,
		"Name", json_object_new_string(secname));

	json_object_object_add(body,
		"Type", json_object_new_string(sh_type_string(shdr)));

	snprintf(buffer, sizeof(buffer), "%#016lx", shdr->sh_addr);
	json_object_object_add(body,
		"Address", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%#08lx", shdr->sh_offset);
	json_object_object_add(body,
		"Offset", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%#016lx", shdr->sh_size);
	json_object_object_add(body,
		"Size", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%#016lx", shdr->sh_entsize);
	json_object_object_add(body,
		"EntSize", json_object_new_string(buffer));

	json_object_object_add(body,
		"Flags", json_object_new_string(
			sh_flags_string(shdr, buffer, sizeof(buffer))));

	json_object_object_add(body,
		"Link", json_object_new_int64(shdr->sh_link));

	json_object_object_add(body,
		"Info", json_object_new_int64(shdr->sh_info));

	json_object_object_add(body,
		"AddrAlign", json_object_new_int64(shdr->sh_addralign));

	/* Foot */
	json_object_object_add(foot,
		"Version", json_object_new_string(elftools_version()));

	return root;
}
#endif

int print_json_shdr(const GElf_Shdr *shdr, const char *secname)
{
#ifdef HAVE_JSON_C_LIBRARIES
	json_object *root = json_shdr(shdr, secname);
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

