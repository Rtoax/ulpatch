#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>

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

/* Packaging metadata as defined on
 * https://systemd.io/COREDUMP_PACKAGE_METADATA/ */
#ifndef NT_FDO_PACKAGING_METADATA
#define NT_FDO_PACKAGING_METADATA 0xcafe1a7e
#endif

const char *n_type_core_string(GElf_Nhdr *nhdr)
{
	const char *res = NULL;

	static const char *knowntypes[] = {
#define KNOWNSTYPE(name) [NT_##name] = #name
	KNOWNSTYPE (PRSTATUS),
	KNOWNSTYPE (FPREGSET),
	KNOWNSTYPE (PRPSINFO),
	KNOWNSTYPE (TASKSTRUCT),
	KNOWNSTYPE (PLATFORM),
	KNOWNSTYPE (AUXV),
	KNOWNSTYPE (GWINDOWS),
	KNOWNSTYPE (ASRS),
	KNOWNSTYPE (PSTATUS),
	KNOWNSTYPE (PSINFO),
	KNOWNSTYPE (PRCRED),
	KNOWNSTYPE (UTSNAME),
	KNOWNSTYPE (LWPSTATUS),
	KNOWNSTYPE (LWPSINFO),
	KNOWNSTYPE (PRFPXREG)
#undef KNOWNSTYPE
	};
	if (nhdr->n_type < ARRAY_SIZE(knowntypes)
		&& knowntypes[nhdr->n_type] != NULL) {
		res = knowntypes[nhdr->n_type];
	} else {
		switch (nhdr->n_type) {
#define KNOWNSTYPE(name) case NT_##name: res = #name; break
		KNOWNSTYPE (PRXFPREG);
		KNOWNSTYPE (PPC_VMX);
		KNOWNSTYPE (PPC_SPE);
		KNOWNSTYPE (PPC_VSX);
		KNOWNSTYPE (PPC_TM_SPR);
		KNOWNSTYPE (386_TLS);
		KNOWNSTYPE (386_IOPERM);
		KNOWNSTYPE (X86_XSTATE);
		KNOWNSTYPE (S390_HIGH_GPRS);
		KNOWNSTYPE (S390_TIMER);
		KNOWNSTYPE (S390_TODCMP);
		KNOWNSTYPE (S390_TODPREG);
		KNOWNSTYPE (S390_CTRS);
		KNOWNSTYPE (S390_PREFIX);
		KNOWNSTYPE (S390_LAST_BREAK);
		KNOWNSTYPE (S390_SYSTEM_CALL);
		KNOWNSTYPE (ARM_VFP);
		KNOWNSTYPE (ARM_TLS);
		KNOWNSTYPE (ARM_HW_BREAK);
		KNOWNSTYPE (ARM_HW_WATCH);
		KNOWNSTYPE (ARM_SYSTEM_CALL);
		KNOWNSTYPE (SIGINFO);
		KNOWNSTYPE (FILE);
#undef KNOWNSTYPE

		default:
		res = "<unknown>";
		}
	}

	return res;
}

const char *n_type_object_string(GElf_Nhdr *nhdr, const char *name,
	uint32_t type, GElf_Word descsz, char *buf, size_t len)
{
	const char *res = NULL;

	if (strcmp(name, "stapsdt") == 0) {
		snprintf(buf, len, "Version: %" PRIu32, type);
		return buf;
	}

#if defined(GO_NOTE_TYPE_H)
	static const char *goknowntypes[] = {
#define KNOWNSTYPE(name) [ELF_NOTE_GO##name] = #name
	KNOWNSTYPE (PKGLIST),
	KNOWNSTYPE (ABIHASH),
	KNOWNSTYPE (DEPS),
	KNOWNSTYPE (BUILDID),
	NULL,
#undef KNOWNSTYPE
	};
	if (strcmp(name, "Go") == 0) {
		if (type < ARRAY_SIZE(goknowntypes)
			&& goknowntypes[type] != NULL)
			return goknowntypes[type];
		else {
			snprintf(buf, len, "%s: %" PRIu32 "<unknown>", type);
			return buf;
		}
	}
#endif

	if (startswith(name, ELF_NOTE_GNU_BUILD_ATTRIBUTE_PREFIX)) {

		/* GNU Build Attribute notes (ab)use the owner name to store
		 * most of their data.  Don't decode everything here.  Just
		 * the type.*/
		char *t = buf;
		const char *gba = "GNU Build Attribute";
		int w = snprintf(t, len, "%s ", gba);
		t += w;
		len -= w;

		if (type == NT_GNU_BUILD_ATTRIBUTE_OPEN)
			snprintf(t, len, "OPEN");
		else if (type == NT_GNU_BUILD_ATTRIBUTE_FUNC)
			snprintf(t, len, "FUNC");
		else
			snprintf(t, len, "%x", type);

		return buf;
	}

	if (strcmp(name, "FDO") == 0 && type == NT_FDO_PACKAGING_METADATA)
		return "FDO_PACKAGING_METADATA";

	if (strcmp(name, "GNU") != 0) {

		/* NT_VERSION is special, all data is in the name.  */
		if (descsz == 0 && type == NT_VERSION)
			return "VERSION";

		snprintf(buf, len, "%s: %" PRIu32, "<unknown>", type);
		return buf;
	}

	/* And finally all the "GNU" note types.  */
	static const char *knowntypes[] = {
#define KNOWNSTYPE(name) [NT_##name] = #name
		KNOWNSTYPE (GNU_ABI_TAG),
		KNOWNSTYPE (GNU_HWCAP),
		KNOWNSTYPE (GNU_BUILD_ID),
		KNOWNSTYPE (GNU_GOLD_VERSION),
		KNOWNSTYPE (GNU_PROPERTY_TYPE_0),
#undef KNOWNSTYPE
	};

	/* Handle standard names.  */
	if (type < ARRAY_SIZE(knowntypes) && knowntypes[type] != NULL)
		res = knowntypes[type];

	else {
		snprintf(buf, len, "%s: %" PRIu32, "<unknown>", type);
		res = buf;
	}

	return res;
}

static void handle_auxv_note(struct elf_file *elf, GElf_Word descsz,
	GElf_Off desc_pos)
{
#if 1
	Elf_Data *data = elf_getdata_rawchunk(elf->elf,
		desc_pos, descsz, ELF_T_AUXV);
	if (data == NULL) {
elf_error:
		lerror("cannot convert core note data: %s", elf_errmsg(-1));
		return;
	}

	size_t i;
	const size_t nauxv =
		descsz / gelf_fsize(elf->elf, ELF_T_AUXV, 1, EV_CURRENT);

	for (i = 0; i < nauxv; ++i) {
		GElf_auxv_t av_mem;
		GElf_auxv_t *av = gelf_getauxv(data, i, &av_mem);
		if (av == NULL)
			goto elf_error;

		const char *name;
		const char *fmt;

		if (auxv_type_info(av->a_type, &name, &fmt) == 0) {
			/* Unknown type.  */
			if (av->a_un.a_val == 0)
				printf ("    %" PRIu64 "\n", av->a_type);
			else
				printf ("    %" PRIu64 ": %#" PRIx64 "\n",
					av->a_type, av->a_un.a_val);
		} else {

			switch (fmt[0]) {
			case '\0': /* Normally zero. */
				if (av->a_un.a_val == 0) {
					printf ("    %s\n", name);
					break;
				}
			FALLTHROUGH;
			case 'x':		/* hex */
			case 'p':		/* address */
			case 's':		/* address of string */
				printf ("    %s: %#" PRIx64 "\n", name, av->a_un.a_val);
				break;
			case 'u':
				printf ("    %s: %" PRIu64 "\n", name, av->a_un.a_val);
				break;
			case 'd':
				printf ("    %s: %" PRId64 "\n", name, av->a_un.a_val);
				break;

			case 'b':
				printf ("    %s: %#" PRIx64 "  ", name, av->a_un.a_val);
				GElf_Xword bit = 1;
				const char *pfx = "<";
				const char *p = NULL;
				for (p = fmt + 1; *p != 0; p = strchr(p, '\0') + 1) {
					if (av->a_un.a_val & bit) {
						printf ("%s%s", pfx, p);
						pfx = " ";
					}
					bit <<= 1;
				}
				printf (">\n");
				break;

			default:
				abort();
			}
		}
	}
#endif
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
			startswith(name, ELF_NOTE_GNU_BUILD_ATTRIBUTE_PREFIX);

		const char *print_name = (is_gnu_build_attr
			? ELF_NOTE_GNU_BUILD_ATTRIBUTE_PREFIX : name);

		size_t print_namesz = (is_gnu_build_attr
			? strlen (print_name) : nhdr.n_namesz);

		char buf[100];
		printf ("  %-13.*s  %9" PRId32 "  %s\n",
			(int) print_namesz, print_name, nhdr.n_descsz,
			elf->ehdr->e_type == ET_CORE
			? n_type_core_string(&nhdr)
			: n_type_object_string(&nhdr, name,
				nhdr.n_type, nhdr.n_descsz, buf, sizeof(buf)));
#if 1
		/* Filter out invalid entries.  */
		if (memchr(name, '\0', nhdr.n_namesz) != NULL
			/* XXX For now help broken Linux kernels.  */
			|| 1)
		{
			if (elf->ehdr->e_type == ET_CORE) {
				if (nhdr.n_type == NT_AUXV
					&& (nhdr.n_namesz == 4 /* Broken old Linux kernels.  */
						|| (nhdr.n_namesz == 5 && name[4] == '\0'))
					&& !memcmp (name, "CORE", 4))
				{
					handle_auxv_note(elf, nhdr.n_descsz,
						shdr->sh_offset + desc_offset);
#if 0
				} else if (nhdr.n_namesz == 5 && strcmp (name, "CORE") == 0) {

					switch (nhdr.n_type) {
					case NT_SIGINFO:
						handle_siginfo_note(ebl->elf, nhdr.n_descsz,
							start + desc_offset);
						break;

					case NT_FILE:
						handle_file_note(ebl->elf, nhdr.n_descsz,
							start + desc_offset);
						break;

					default:
						handle_core_note(ebl, &nhdr, name, desc);
					}
				} else {
					handle_core_note(ebl, &nhdr, name, desc);
#endif
				}
			} else {
#if 0
				ebl_object_note(ebl, nhdr.n_namesz, name, nhdr.n_type,
					nhdr.n_descsz, desc);
#endif
			}
		}
#endif
	}
	if (offset == data->d_size)
		return 0;

bad_note:
	lerror("cannot get content of note: %s",
		data != NULL ? "garbage data" : elf_errmsg(-1));
	return -ENODATA;
}

