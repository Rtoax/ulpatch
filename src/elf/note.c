#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>

#if defined(HAVE_ELFUTILS_DEVEL)
#include <elfutils/elf-knowledge.h>
#else
#define ELF_NOTE_GNU_BUILD_ATTRIBUTE_PREFIX "GA"
#endif

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>


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

int handle_notes(struct elf_file *elf, GElf_Shdr *shdr, Elf_Scn *scn)
{
	Elf_Data *data = elf_getdata(scn, NULL);

	if (!data)
		goto bad_note;

#if 0

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
		 * prefix here, then use the rest later as data.  */
		bool is_gnu_build_attr =
			startswith(name, ELF_NOTE_GNU_BUILD_ATTRIBUTE_PREFIX);

		const char *print_name = (is_gnu_build_attr
			? ELF_NOTE_GNU_BUILD_ATTRIBUTE_PREFIX : name);

		size_t print_namesz = (is_gnu_build_attr
			? strlen (print_name) : nhdr.n_namesz);

		printf ("  %-13.*s  %9" PRId32 "  %s\n",
			(int) print_namesz, print_name, nhdr.n_descsz,
			elf->ehdr->e_type == ET_CORE
			? n_type_core_string(&nhdr)
			: "TODO: object note type");
	}
	// TODO
#endif

	return 0;

bad_note:
	return -ENODATA;
}
