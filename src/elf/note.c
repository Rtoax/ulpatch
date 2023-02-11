// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>
#include <byteswap.h>
#include <endian.h>
#include <malloc.h>
#include <stdlib.h>
#include <assert.h>

#if defined(HAVE_ELFUTILS_DEVEL)
#include <elfutils/elf-knowledge.h>
#else
#define ELF_NOTE_GNU_BUILD_ATTRIBUTE_PREFIX "GA"
#define NT_GNU_BUILD_ATTRIBUTE_OPEN 0x100
#define NT_GNU_BUILD_ATTRIBUTE_FUNC 0x101
#endif

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>

#if defined(__aarch64__) || defined(__x86_64__)
/* AArch64 specific GNU properties.
 * see elfutils/libelf/elf.h or linux/elf.h */
# ifndef GNU_PROPERTY_AARCH64_FEATURE_1_AND
#  define GNU_PROPERTY_AARCH64_FEATURE_1_AND  0xc0000000
# endif

# ifndef GNU_PROPERTY_AARCH64_FEATURE_1_BTI
#  define GNU_PROPERTY_AARCH64_FEATURE_1_BTI  (1U << 0)
# endif
# ifndef GNU_PROPERTY_AARCH64_FEATURE_1_PAC
#  define GNU_PROPERTY_AARCH64_FEATURE_1_PAC  (1U << 1)
# endif
#endif

/* Packaging metadata as defined on
 * https://systemd.io/COREDUMP_PACKAGE_METADATA/ */
#ifndef NT_FDO_PACKAGING_METADATA
#define NT_FDO_PACKAGING_METADATA 0xcafe1a7e
#endif



static const void *
convert(Elf *core, Elf_Type type, uint_fast16_t count,
	void *value, const void *data, size_t size)
{
	Elf_Data valuedata = {
		.d_type = type,
		.d_buf = value,
		.d_size = size ?: gelf_fsize (core, type, count, EV_CURRENT),
		.d_version = EV_CURRENT,
	};

	Elf_Data indata = {
		.d_type = type,
		.d_buf = (void *) data,
		.d_size = valuedata.d_size,
		.d_version = EV_CURRENT,
	};

	// not support 32bit yet
	Elf_Data *d = (gelf_getclass(core) == ELFCLASS32
		? elf32_xlatetom : elf64_xlatetom)
			(&valuedata, &indata, elf_getident (core, NULL)[EI_DATA]);
	if (d == NULL) {
		lerror("cannot convert core note data: %s", elf_errmsg(-1));
		return 0;
	}

	return data + indata.d_size;
}

typedef uint8_t GElf_Byte;

static bool
buf_has_data(unsigned char const *ptr, unsigned char const *end, size_t sz)
{
	return ptr < end && (size_t) (end - ptr) >= sz;
}

static bool
buf_read_int(Elf *core, unsigned char const **ptrp, unsigned char const *end,
	int *retp)
{
	if (! buf_has_data(*ptrp, end, 4))
		return false;

	*ptrp = convert (core, ELF_T_WORD, 1, retp, *ptrp, 4);
	return true;
}

static bool
buf_read_ulong(Elf *core, unsigned char const **ptrp, unsigned char const *end,
	uint64_t *retp)
{
	size_t sz = gelf_fsize(core, ELF_T_ADDR, 1, EV_CURRENT);
	if (! buf_has_data (*ptrp, end, sz))
		return false;

	union {
		uint64_t u64;
		uint32_t u32;
	} u;

	*ptrp = convert(core, ELF_T_ADDR, 1, &u, *ptrp, sz);

	if (sz == 4)
		*retp = u.u32;
	else
		*retp = u.u64;
	return true;
}

static void __unused
handle_siginfo_note(struct elf_file *elf, GElf_Word descsz, GElf_Off desc_pos)
{
	Elf *core = elf->elf;
	Elf_Data *data = elf_getdata_rawchunk (core, desc_pos, descsz, ELF_T_BYTE);
	if (data == NULL) {
		lerror("cannot convert core note data: %s", elf_errmsg (-1));
		return;
	}

	unsigned char const *ptr = data->d_buf;
	unsigned char const *const end = data->d_buf + data->d_size;

	/* Siginfo head is three ints: signal number, error number, origin
	 * code. */
	int si_signo, si_errno, si_code;
	if (! buf_read_int (core, &ptr, end, &si_signo)
		|| ! buf_read_int (core, &ptr, end, &si_errno)
		|| ! buf_read_int (core, &ptr, end, &si_code))
	{
fail:
		printf("    Not enough data in NT_SIGINFO note.\n");
		return;
	}

	/* Next is a pointer-aligned union of structures.  On 64-bit
	 * machines, that implies a word of padding.  */
	if (gelf_getclass(core) == ELFCLASS64)
		ptr += 4;

	printf("    si_signo: %d, si_errno: %d, si_code: %d\n",
		si_signo, si_errno, si_code);

	if (si_code > 0) {
		switch (si_signo) {
		case CORE_SIGILL:
		case CORE_SIGFPE:
		case CORE_SIGSEGV:
		case CORE_SIGBUS:
		{
			uint64_t addr;
			if (! buf_read_ulong (core, &ptr, end, &addr))
				goto fail;
			printf("    fault address: %#" PRIx64 "\n", addr);
			break;
		}
		default:
			;
		}

	} else if (si_code == CORE_SI_USER) {
		int pid, uid;
		if (! buf_read_int (core, &ptr, end, &pid)
			|| ! buf_read_int (core, &ptr, end, &uid))
			goto fail;
		printf("    sender PID: %d, sender UID: %d\n", pid, uid);
	}
}

static void __unused
handle_file_note (struct elf_file *elf, GElf_Word descsz, GElf_Off desc_pos)
{
	Elf *core = elf->elf;
	Elf_Data *data = elf_getdata_rawchunk (core, desc_pos, descsz, ELF_T_BYTE);
	if (data == NULL) {
		lerror("cannot convert core note data: %s", elf_errmsg (-1));
	}

	unsigned char const *ptr = data->d_buf;
	unsigned char const *const end = data->d_buf + data->d_size;

	uint64_t count, page_size;
	if (! buf_read_ulong (core, &ptr, end, &count)
		|| ! buf_read_ulong (core, &ptr, end, &page_size))
	{
fail:
		printf("    Not enough data in NT_FILE note.\n");
		return;
	}

	size_t addrsize = gelf_fsize (core, ELF_T_ADDR, 1, EV_CURRENT);
	uint64_t maxcount = (size_t) (end - ptr) / (3 * addrsize);
	if (count > maxcount)
		goto fail;

	/* Where file names are stored.  */
	unsigned char const *const fstart = ptr + 3 * count * addrsize;
	char const *fptr = (char *) fstart;

	printf("    %" PRId64 " files:\n", count);
	for (uint64_t i = 0; i < count; ++i) {
		uint64_t mstart, mend, moffset;
		if (! buf_read_ulong (core, &ptr, fstart, &mstart)
		  || ! buf_read_ulong (core, &ptr, fstart, &mend)
		  || ! buf_read_ulong (core, &ptr, fstart, &moffset))
		{
			goto fail;
		}

		const char *fnext = memchr (fptr, '\0', (char *) end - fptr);
		if (fnext == NULL)
			goto fail;

		int __unused ct = printf("      %08" PRIx64 "-%08" PRIx64
	       " %08" PRIx64 " %" PRId64,
	       mstart, mend, moffset * page_size, mend - mstart);
		printf("%*s%s\n", ct > 50 ? 3 : 53 - ct, "", fptr);

		fptr = fnext + 1;
	}
}

static void __unused
elf_object_note(struct elf_file *elf, uint32_t namesz, const char *name,
	uint32_t type, uint32_t descsz, const char *desc)
{
	/* NT_VERSION doesn't have any info.  All data is in the name.  */
	if (descsz == 0 && type == NT_VERSION)
		return;

	/* Everything else should have the "GNU" owner name.  */
	if (strcmp("GNU", name) != 0)
		return;

	switch (type) {
	case NT_GNU_BUILD_ID:
		if (strcmp(name, "GNU") == 0 && descsz > 0) {
			uint_fast32_t i;
			char v[3] = {};
			char *build_id = malloc(descsz * 2 + 1);
			assert(build_id && "Malloc fatal.");

			// save Build ID, see:
			// $ readelf -n /bin/ls | grep "Build ID"
			//  Build ID: 49c2fad65d0c2df70025644c9bc7485b28bab899

			for (i = 0; i < descsz - 1; ++i) {
				sprintf(v, "%02" PRIx8, (uint8_t) desc[i]);
				build_id[i * 2] = v[0];
				build_id[i * 2 + 1] = v[1];
			}
			sprintf(v, "%02" PRIx8, (uint8_t) desc[i]);
			build_id[i * 2] = v[0];
			build_id[i * 2 + 1] = v[1];
			build_id[i * 2 + 2] = '\0';

			ldebug("Build ID: %s\n", build_id);

			elf->build_id = build_id;
		}
		break;

	default:
		/* Unknown type.  */
		break;
	}
}

int handle_notes(struct elf_file *elf, GElf_Shdr *shdr, Elf_Scn *scn)
{
	Elf_Data *data = elf_getdata(scn, NULL);

	if (!data)
		goto bad_note;

	size_t offset  = 0;
	GElf_Nhdr nhdr;
	size_t name_offset;
	size_t desc_offset;

	while (offset < data->d_size
		&& (offset = gelf_getnote(data, offset,
			&nhdr, &name_offset, &desc_offset)) > 0)
	{
		const char *name = nhdr.n_namesz == 0 ? "" : data->d_buf + name_offset;
		const char __unused *desc = data->d_buf + desc_offset;

		/* GNU Build Attributes are weird, they store most of their data
		 * into the owner name field.  Extract just the owner name
		 * prefix here, then use the rest later as data. */
		bool is_gnu_build_attr =
			upatch_startswith(name, ELF_NOTE_GNU_BUILD_ATTRIBUTE_PREFIX);

		// if name has "GA" prefix
		const char *print_name = (is_gnu_build_attr
			? ELF_NOTE_GNU_BUILD_ATTRIBUTE_PREFIX : name);

		size_t __unused print_namesz = (is_gnu_build_attr
			? strlen (print_name) : nhdr.n_namesz);

		char __unused buf[100];
		/* Filter out invalid entries.  */
		if (memchr(name, '\0', nhdr.n_namesz) != NULL
			/* XXX For now help broken Linux kernels.  */
			|| 1)
		{
			if (elf->ehdr->e_type == ET_CORE) {
				// TODO
			} else {
				elf_object_note(elf, nhdr.n_namesz, name, nhdr.n_type,
					nhdr.n_descsz, desc);
			}
		}
	}
	if (offset == data->d_size)
		return 0;

bad_note:
	lerror("cannot get content of note: %s",
		data != NULL ? "garbage data" : elf_errmsg(-1));
	return -ENODATA;
}

