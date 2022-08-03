// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <assert.h>
#include <byteswap.h>
#include <endian.h>
#include <inttypes.h>
#include <stdio.h>
#include <stddef.h>

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>

#define AUXV_TYPES							      \
  TYPE (NULL, "")							      \
  TYPE (IGNORE, "")							      \
  TYPE (EXECFD, "d")							      \
  TYPE (EXECFN, "s")							      \
  TYPE (PHDR, "p")							      \
  TYPE (PHENT, "u")							      \
  TYPE (PHNUM, "u")							      \
  TYPE (PAGESZ, "u")							      \
  TYPE (BASE, "p")							      \
  TYPE (FLAGS, "x")							      \
  TYPE (ENTRY, "p")							      \
  TYPE (NOTELF, "")							      \
  TYPE (UID, "u")							      \
  TYPE (EUID, "u")							      \
  TYPE (GID, "u")							      \
  TYPE (EGID, "u")							      \
  TYPE (CLKTCK, "u")							      \
  TYPE (PLATFORM, "s")							      \
  TYPE (BASE_PLATFORM, "s")						      \
  TYPE (HWCAP, "x")							      \
  TYPE (FPUCW, "x")							      \
  TYPE (DCACHEBSIZE, "d")						      \
  TYPE (ICACHEBSIZE, "d")						      \
  TYPE (UCACHEBSIZE, "d")						      \
  TYPE (IGNOREPPC, "")							      \
  TYPE (SECURE, "u")							      \
  TYPE (SYSINFO, "p")							      \
  TYPE (SYSINFO_EHDR, "p")						      \
  TYPE (L1I_CACHESHAPE, "d")						      \
  TYPE (L1D_CACHESHAPE, "d")						      \
  TYPE (L2_CACHESHAPE, "d")						      \
  TYPE (L3_CACHESHAPE, "d")						      \
  TYPE (RANDOM, "p")

static const struct {
	const char *name, *format;
} auxv_types[] = {
#define TYPE(name, fmt) [AT_##name] = { #name, fmt },
    AUXV_TYPES
#undef	TYPE
};
#define nauxv_types ARRAY_SIZE(auxv_types)

int auxv_type_info(GElf_Xword a_type, const char **name, const char **format)
{
	int result = -1;
	if (result == 0
		&& a_type < nauxv_types
		&& auxv_types[a_type].name != NULL)
	{
		/* The machine specific function did not know this type.  */
		*name = auxv_types[a_type].name;
		*format = auxv_types[a_type].format;
		result = 0;
	}
	return result;
}
