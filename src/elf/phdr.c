#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>

const char *p_type_string(const GElf_Phdr *phdr)
{
	switch (phdr->p_type) {
	case PT_NULL: /* Program header table entry unused */
		return "NULL";
	case PT_LOAD: /* Loadable program segment */
		return "LOAD";
	case PT_DYNAMIC: /* Dynamic linking information */
		return "DYNAMIC";
	case PT_INTERP:  /* Program interpreter */
		return "INTERP";
	case PT_NOTE: /* Auxiliary information */
		return "NOTE";
	case PT_SHLIB: /* Reserved */
		return "SHLIB";
	case PT_PHDR: /* Entry for header table itself */
		return "PHDR";
	case PT_TLS: /* Thread-local storage segment */
		return "TLS";
	case PT_NUM: /* Number of defined types */
		return "NUM";
	case PT_LOOS: /* Start of OS-specific */
		return "LOOS";
	case PT_GNU_EH_FRAME: /* GCC .eh_frame_hdr segment */
		return "GNU_EH_FRAM";
	case PT_GNU_STACK: /* Indicates stack executability */
		return "GNU_STACK";
	case PT_GNU_RELRO: /* Read-only after relocation */
		return "GNU_RELRO";
#if defined(__x86_64__) && defined(PT_GNU_PROPERTY)
	case PT_GNU_PROPERTY: /* GNU property */
		return "GNU_PROPERTY";
#endif
	case PT_SUNWBSS: /* Sun Specific segment, same as PT_LOSUNW */
		return "SUNWBSS";
	case PT_SUNWSTACK: /* Stack segment */
		return "SUNWSTACK";
	case PT_HIOS: /* End of OS-specific, same as PT_HISUNW */
		return "HIOS";
	case PT_LOPROC: /* Start of processor-specific */
		return "LOPROC";
	case PT_HIPROC: /* End of processor-specific */
		return "HIPROC";
	default:
		return "unknown";
		break;
	}
	return "unknown";
}

int print_phdr(const GElf_Phdr *phdr)
{
	printf(
		"\033[7mType             Offset             VirtAddr           PhysAddr     \033[m\n"
		"%-16s %#016lx %#016lx %#016lx\n"
		"                 FileSiz            MemSiz              Flags  Align\n"
		"%-16s %#016lx %#016lx %8x %8ld\n",
		p_type_string(phdr), phdr->p_offset, phdr->p_vaddr, phdr->p_paddr,
		"", phdr->p_filesz, phdr->p_memsz, phdr->p_flags, phdr->p_align
	);
	return 0;
}

#ifdef HAVE_JSON_C_LIBRARIES
json_object *json_phdr(const GElf_Phdr *phdr)
{
	char buffer[256];

	json_object *root = json_object_new_object();

	json_object *head = json_object_new_object();
	json_object *body = json_object_new_object();
	json_object *foot = json_object_new_object();

	json_object_object_add(root, "Head", head);
	json_object_object_add(root, "Body", body);
	json_object_object_add(root, "Foot", foot);

	/* Head */
	json_object_object_add(head,
		"Type", json_object_new_string("ELF Program Head"));

	/* Body */
	json_object_object_add(body,
		"Type", json_object_new_string(p_type_string(phdr)));

	snprintf(buffer, sizeof(buffer), "%#016lx", phdr->p_offset);
	json_object_object_add(body,
		"Offset", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%#016lx", phdr->p_vaddr);
	json_object_object_add(body,
		"VirtAddr", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%#016lx", phdr->p_paddr);
	json_object_object_add(body,
		"PhysAddr", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%#016lx", phdr->p_filesz);
	json_object_object_add(body,
		"FileSize", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%#016lx", phdr->p_memsz);
	json_object_object_add(body,
		"MemSize", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%x", phdr->p_flags);
	json_object_object_add(body,
		"Flags", json_object_new_string(buffer));

	snprintf(buffer, sizeof(buffer), "%ld", phdr->p_align);
	json_object_object_add(body,
		"Align", json_object_new_string(buffer));

	/* Foot */
	json_object_object_add(foot,
		"Version", json_object_new_string(elftools_version()));

	return root;
}
#endif

int print_json_phdr(const GElf_Phdr *phdr)
{
#ifdef HAVE_JSON_C_LIBRARIES
	json_object *root = json_phdr(phdr);
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

