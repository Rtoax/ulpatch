#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>


const char *st_bind_string(const GElf_Sym *sym)
{
	switch (GELF_ST_BIND(sym->st_info)) {
	case STB_LOCAL:   return "LOCAL";	/* Local symbol */
	case STB_GLOBAL:  return "GLOBAL";	/* Global symbol */
	case STB_WEAK:    return "WEAK";	/* Weak symbol */
	case STB_NUM:     return "NUM";		/* Number of defined types.  */
	case STB_LOOS:    return "LOOS";	/* Start of OS-specific */
	// same as STB_LOOS
	//case STB_GNU_UNIQUE:  return "GNU_UNIQUE";/* Unique symbol.  */
	case STB_HIOS:    return "HIOS";	/* End of OS-specific */
	case STB_LOPROC:  return "LOPROC";	/* Start of processor-specific */
	case STB_HIPROC:  return "HIPROC";	/* End of processor-specific */
	}
	return "UNKNOWN";
}

const char *st_type_string(const GElf_Sym *sym)
{
	switch (GELF_ST_TYPE(sym->st_info)) {
	case STT_NOTYPE:  return "NOTYPE";	/* Symbol type is unspecified */
	case STT_OBJECT:  return "OBJECT";	/* Symbol is a data object */
	case STT_FUNC:    return "FUNC";	/* Symbol is a code object */
	case STT_SECTION: return "SECTION";	/* Symbol associated with a section */
	case STT_FILE:    return "FILE";	/* Symbol's name is file name */
	case STT_COMMON:  return "COMMON";	/* Symbol is a common data object */
	case STT_TLS:     return "TLS";		/* Symbol is thread-local data object*/
	case STT_NUM:     return "NUM";		/* Number of defined types.  */
	case STT_LOOS:    return "LOOS";	/* Start of OS-specific */
	// same as STT_LOOS
	//case STT_GNU_IFUNC: return "GNU_IFUNC";/* Symbol is indirect code object */
	case STT_HIOS:    return "HIOS";	/* End of OS-specific */
	case STT_LOPROC:  return "LOPROC";	/* Start of processor-specific */
	case STT_HIPROC:  return "HIPROC";	/* End of processor-specific */
	}
	return "UNKNOWN";
}

const char *st_visibility_string(const GElf_Sym *sym)
{
	switch (GELF_ST_VISIBILITY(sym->st_info)) {
	case STV_DEFAULT:   return "DEFAULT"; /* Default symbol visibility rules */
	case STV_INTERNAL:  return "INTERNAL";/* Processor specific hidden class */
	case STV_HIDDEN:    return "HIDDEN";  /* Sym unavailable in other modules */
	case STV_PROTECTED: return "PROTECTED";/* Not preemptible, not exported */
	}
	return "UNKNOWN";
}

// stderr@GLIBC_2.2.5
// symname = stderr
// vername = GLIBC_2.2.5
int print_sym(const GElf_Sym *sym, const char *symname, const char *vername)
{
	printf(
	"%s%s%s\n",
	symname, vername?"@":"", vername?:""
	);

	return 0;
}

#ifdef HAVE_JSON_C_LIBRARIES
json_object *json_sym(const GElf_Sym *sym, const char *symname,
	const char *vername)
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
		"Type", json_object_new_string("ELF Symbol"));

	/* Body */
#if 0
	json_object_object_add(body,
		"Name", json_object_new_string(secname));

	snprintf(buffer, sizeof(buffer), "%#016lx", shdr->sh_addr);
	json_object_object_add(body,
		"Address", json_object_new_string(buffer));

	json_object_object_add(body,
		"Link", json_object_new_int64(shdr->sh_link));
#endif
	return root;
}
#endif

int print_json_sym(const GElf_Sym *sym, const char *symname,
	const char *vername)
{
#ifdef HAVE_JSON_C_LIBRARIES
	json_object *root = json_sym(sym, symname, vername);
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

GElf_Sym *get_next_symbol(struct elf_file *elf, Elf_Scn *scn,
	int isym, size_t *nsyms,
	GElf_Sym *sym_mem, char **symname, char **pversion)
{
	Elf_Data *data = elf_getdata(scn, NULL);
	size_t ndx = elf_ndxscn(scn);
	GElf_Shdr *shdr = &elf->shdrs[ndx];

	*nsyms = (data->d_size / gelf_fsize(elf->elf, ELF_T_SYM, 1, EV_CURRENT));
	*pversion = NULL;
	*symname = NULL;

	if (isym <= 0 && isym >= *nsyms) {
		return NULL;
	}

	Elf32_Word xndx;
	GElf_Sym *sym = gelf_getsymshndx(data, elf->xndx_data, isym,
		sym_mem, &xndx);

	if (unlikely(sym == NULL))
		return NULL;

	/* Determine the real section index.  */
	if (likely(sym->st_shndx != SHN_XINDEX))
		xndx = sym->st_shndx;

	if (GELF_ST_TYPE(sym->st_info) == STT_SECTION
		&& sym->st_shndx == elf->shdrstrndx) {

		lwarning("WARNING:"
		" symbol table [%zd] contains section symbol %zd"
		" for old shdrstrndx %zd\n", ndx, isym, elf->shdrstrndx);
	}

	// Get symbol name string
	*symname = elf_strptr(elf->elf, shdr->sh_link, sym->st_name);

	if (elf->versym_data != NULL) {
		/* Get the version information.  */
		GElf_Versym versym_mem;
		GElf_Versym *versym = gelf_getversym(elf->versym_data,
			isym, &versym_mem);

		if (versym != NULL && ((*versym & 0x8000) != 0 || *versym > 1)) {
			bool is_nobits = false;
			bool check_def = xndx != SHN_UNDEF;

			if (xndx < SHN_LORESERVE || sym->st_shndx == SHN_XINDEX) {
				GElf_Shdr symshdr_mem;
				GElf_Shdr *symshdr =
					gelf_getshdr(elf_getscn(elf->elf, xndx), &symshdr_mem);

				is_nobits = (symshdr != NULL
					&& symshdr->sh_type == SHT_NOBITS);
			}

			if (is_nobits || ! check_def) {
				/* We must test both.  */
				GElf_Vernaux vernaux_mem;
				GElf_Vernaux *vernaux = NULL;
				size_t vn_offset = 0;

				GElf_Verneed verneed_mem;
				GElf_Verneed *verneed = gelf_getverneed(elf->verneed_data,
					0, &verneed_mem);

				while (verneed != NULL) {

					size_t vna_offset = vn_offset;

					vernaux = gelf_getvernaux(elf->verneed_data,
						vna_offset += verneed->vn_aux, &vernaux_mem);

					while (vernaux != NULL
						&& vernaux->vna_other != *versym
						&& vernaux->vna_next != 0
						&& (elf->verneed_data->d_size - vna_offset
							>= vernaux->vna_next)) {
						/* Update the offset.  */
						vna_offset += vernaux->vna_next;
						vernaux = (vernaux->vna_next == 0
							? NULL
							: gelf_getvernaux(elf->verneed_data,
								vna_offset,
								&vernaux_mem));
					}

					/* Check whether we found the version.  */
					if (vernaux != NULL && vernaux->vna_other == *versym)
						break;

					if (elf->verneed_data->d_size - vn_offset
						< verneed->vn_next)
						break;

					vn_offset += verneed->vn_next;
					verneed = (verneed->vn_next == 0
						? NULL
						: gelf_getverneed(elf->verneed_data, vn_offset,
							&verneed_mem));
				}

				if (vernaux != NULL && vernaux->vna_other == *versym) {
					*pversion = elf_strptr(elf->elf, elf->verneed_stridx,
							vernaux->vna_name);
					check_def = 0;

				} else if (unlikely (!is_nobits)) {
					lerror("bad dynamic symbol");
				} else {
					check_def = 1;
				}
			}

			if (check_def && *versym != 0x8001) {
				/* We must test both.  */
				size_t vd_offset = 0;

				GElf_Verdef verdef_mem;
				GElf_Verdef *verdef = gelf_getverdef(elf->verdef_data, 0,
					&verdef_mem);

				while (verdef != NULL) {
					/* Found the definition.  */
					if (verdef->vd_ndx == (*versym & 0x7fff))
						break;

					if (elf->verdef_data->d_size - vd_offset
						< verdef->vd_next)
						break;

					vd_offset += verdef->vd_next;
					verdef = (verdef->vd_next == 0
						? NULL
						: gelf_getverdef(elf->verdef_data, vd_offset,
							&verdef_mem));
				}

				if (verdef != NULL) {
					GElf_Verdaux verdaux_mem;
					GElf_Verdaux *verdaux =
						gelf_getverdaux(elf->verdef_data,
							vd_offset + verdef->vd_aux,
						&verdaux_mem);

					if (verdaux != NULL)
						*pversion = elf_strptr(elf->elf, elf->verdef_stridx,
								verdaux->vda_name);
				}
			}
		}
	}
	return sym;
}

int handle_symtab(struct elf_file *elf, Elf_Scn *scn)
{
	size_t nsym = 0, isym = 0;
	GElf_Sym __unused *sym, sym_mem;
	char *symname, *pversion;

	for_each_symbol(elf, scn, sym, sym_mem, isym, nsym, symname, pversion) {

		if (!sym) continue;

		ldebug("%s%s%s\n", symname, pversion?"@":"", pversion?:"");
		// TODO: May you want save 'sym'
	}
	return 0;
}

