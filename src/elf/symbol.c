#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>


int handle_symtab(struct elf_file *elf, Elf_Scn *scn, int type)
{
	int isym;
	Elf_Data *data = elf_getdata(scn, NULL);
	size_t ndx = elf_ndxscn(scn);
	GElf_Shdr *shdr = &elf->shdrs[ndx];

	size_t nsyms = (data->d_size
		/ gelf_fsize(elf->elf, ELF_T_SYM, 1, EV_CURRENT));

	for (isym = 0; isym < nsyms; isym++) {

		Elf32_Word xndx;
		GElf_Sym sym_mem;
		GElf_Sym *sym = gelf_getsymshndx(data, elf->xndx_data, isym, &sym_mem,
					&xndx);

		if (unlikely(sym == NULL))
			continue;

		/* Determine the real section index.  */
		if (likely(sym->st_shndx != SHN_XINDEX))
			xndx = sym->st_shndx;

		if (GELF_ST_TYPE(sym->st_info) == STT_SECTION
			&& sym->st_shndx == elf->shdrstrndx) {

			lwarning("WARNING:"
			" symbol table [%zd] contains section symbol %zd"
			" for old shdrstrndx %zd\n", ndx, isym, elf->shdrstrndx);
		}

		printf("%s %s", sh_type_string(shdr),
			elf_strptr(elf->elf, shdr->sh_link, sym->st_name));

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
						// TODO
						// see readelf --dyn-syms /bin/ls
						printf ("@%s (%u)",
							elf_strptr(elf->elf, elf->verneed_stridx,
								vernaux->vna_name),
							(unsigned int) vernaux->vna_other);
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
							printf((*versym & 0x8000) ? "@%s" : "@@%s",
								elf_strptr(elf->elf, elf->verdef_stridx,
									verdaux->vda_name));
					}
				}
			}
		}
		printf("\n");
	}

	return 0;
}

