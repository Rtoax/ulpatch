// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>
#include <malloc.h>

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>
#include <patch/patch.h>


const char *st_bind_string(const GElf_Sym *sym)
{
	switch (GELF_ST_BIND(sym->st_info)) {
	case STB_LOCAL:   return "LOCAL";	/* Local symbol */
	case STB_GLOBAL:  return "GLOBAL";	/* Global symbol */
	case STB_WEAK:    return "WEAK";	/* Weak symbol */
	case STB_NUM:     return "NUM";		/* Number of defined types.  */
	case STB_LOOS:    return "LOOS";	/* Start of OS-specific */
#if STB_LOOS != STB_GNU_UNIQUE
	case STB_GNU_UNIQUE:  return "GNU_UNIQUE";/* Unique symbol.  */
#endif
	case STB_HIOS:    return "HIOS";	/* End of OS-specific */
	case STB_LOPROC:  return "LOPROC";	/* Start of processor-specific */
	case STB_HIPROC:  return "HIPROC";	/* End of processor-specific */
	}
	return "UNKNOWN";
}

const char *i_st_type_string(const int type)
{
	switch (type) {
	case STT_NOTYPE:  return "NOTYPE";	/* Symbol type is unspecified */
	case STT_OBJECT:  return "OBJECT";	/* Symbol is a data object */
	case STT_FUNC:    return "FUNC";	/* Symbol is a code object */
	case STT_SECTION: return "SECTION";	/* Symbol associated with a section */
	case STT_FILE:    return "FILE";	/* Symbol's name is file name */
	case STT_COMMON:  return "COMMON";	/* Symbol is a common data object */
	case STT_TLS:     return "TLS";		/* Symbol is thread-local data object*/
	case STT_NUM:     return "NUM";		/* Number of defined types.  */
	case STT_LOOS:    return "LOOS";	/* Start of OS-specific */
#if STT_LOOS != STT_GNU_IFUNC
	case STT_GNU_IFUNC: return "GNU_IFUNC";/* Symbol is indirect code object */
#endif
	case STT_HIOS:    return "HIOS";	/* End of OS-specific */
	case STT_LOPROC:  return "LOPROC";	/* Start of processor-specific */
	case STT_HIPROC:  return "HIPROC";	/* End of processor-specific */
	}
	return "UNKNOWN";
}

const char *st_type_string(const GElf_Sym *sym)
{
	return i_st_type_string(GELF_ST_TYPE(sym->st_info));
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

/**
 * stderr@GLIBC_2.2.5
 * symname = stderr
 * vername = GLIBC_2.2.5
 */
int fprint_sym(FILE *fp, const GElf_Sym *sym, const char *symname,
	       const char *vername, bool firstline)
{
	if (!fp)
		fp = stdout;

	if (firstline)
		fprintf(fp, " %-18s %-7s %-8s %-8s %-12s %-4s %-8s\n",
			"Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
	fprintf(fp, " %#018lx %-7ld %-8s %-8s %-12s %-4d %s%s%s\n",
		sym->st_value,
		sym->st_size,
		st_type_string(sym),
		st_bind_string(sym),
		st_visibility_string(sym),
		sym->st_shndx,
		symname, vername ? "@" : "", vername ?: "");

	return 0;
}

const static char *___ftrace_entry_funcs[] = {
	"__cyg_profile_func_enter",
	"__fentry__",
	"mcount",
	"_mcount",
	"__gnu_mcount_nc",
};

/* If compile with -pg, there might be hava mcount() */
bool is_ftrace_entry(char *func)
{
	int i;
	bool ret = false;

	for (i = 0; i < ARRAY_SIZE(___ftrace_entry_funcs); i++) {
		if (!strcmp(___ftrace_entry_funcs[i], func)) {
			ret = true;
			break;
		}
	}

	return ret;
}

int is_undef_symbol(const GElf_Sym *sym)
{
	return sym->st_shndx == SHN_UNDEF || sym->st_shndx >= SHN_LORESERVE;
}

bool is_extern_symbol(const GElf_Sym *sym)
{
	int bind = GELF_ST_BIND(sym->st_info);
	/* externs are symbols w/ type=NOTYPE, bind=GLOBAL|WEAK, section=UND */
	return sym->st_shndx == SHN_UNDEF &&
	       (bind == STB_GLOBAL || bind == STB_WEAK) &&
	       GELF_ST_TYPE(sym->st_info) == STT_NOTYPE;
}

GElf_Sym *get_next_symbol(struct elf_file *elf, Elf_Scn *scn, int isym,
			  size_t *nsyms, GElf_Sym *sym_mem, char **symname,
			  char **pversion)
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
		" symbol table [%zd] contains section symbol %d"
		" for old shdrstrndx %zd\n", ndx, isym, elf->shdrstrndx);
	}

	/* Get symbol name string */
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
	GElf_Sym *sym, sym_mem;
	char *symname, *pversion;

	for (isym = 0, sym = get_next_symbol(elf, scn, isym, &nsym, &sym_mem,
					     &symname, &pversion);
	     isym < nsym;
	     isym++, sym = get_next_symbol(elf, scn, isym, &nsym, &sym_mem,
					   &symname, &pversion)) {

		if (!sym)
			continue;

		ldebug("%s%s%s\n", symname, pversion ? "@" : "",
			pversion ?: "");

		/* save symbol to rbtree */
		struct symbol *s = alloc_symbol(symname, sym);
		link_symbol(elf, s);

		/* make some special handle */
		switch (GELF_ST_TYPE(sym->st_info)) {
		case STT_FUNC:
			if (is_ftrace_entry(symname)) {
				elf->support_ftrace = true;
				lwarning("Found fentry %s\n", symname);
			}
			break;
		default:
			break;
		}
	}
	return 0;
}

/* the @key is (unsigned long)symbol */
int cmp_symbol_name(struct rb_node *n1, unsigned long key)
{
	struct symbol *s1 = rb_entry(n1, struct symbol, node);
	struct symbol *s2 = (struct symbol*)key;

/**
 * FIXME: pthread_create()'s symbol type in ulp is STT_NOTYPE
 */
#if 0
	if (s1->type < s2->type) {
		return -1;
	} else if (s1->type > s2->type) {
		return 1;
	} else
#endif
		return strcmp(s1->name, s2->name);
}

struct symbol *alloc_symbol(const char *name, const GElf_Sym *sym)
{
	struct symbol *s = malloc(sizeof(struct symbol));

	memset(s, 0, sizeof(*s));

	s->name = strdup(name);
	s->type = GELF_ST_TYPE(sym->st_info);

	memcpy(&s->sym, sym, sizeof(GElf_Sym));

	return s;
}

struct symbol *find_symbol(struct elf_file *elf, const char *name, int type)
{
	struct symbol tmp = {
		.name = (char *)name,
		.type = type,
	};
	struct rb_node *node = rb_search_node(&elf->elf_file_symbols,
					      cmp_symbol_name,
					      (unsigned long)&tmp);
	return node ? rb_entry(node, struct symbol, node) : NULL;
}

int for_each_symbol(struct elf_file *elf, void (*handler)(struct elf_file *,
							  struct symbol *,
							  void *),
		    void *arg)
{
	struct symbol *sym;
	struct rb_node *first, *rnode;

	if (!handler) {
		return -EINVAL;
	}

	first = rb_first(&elf->elf_file_symbols);

	for (rnode = first; rnode; rnode = rb_next(rnode)) {
		sym = rb_entry(rnode, struct symbol, node);
		handler(elf, sym, arg);
	}
	return 0;
}

/* Insert OK, return 0, else return -1 */
int link_symbol(struct elf_file *elf, struct symbol *s)
{
	int i, nphdrs;
	struct rb_node *node;
	GElf_Section sec = s->sym.st_shndx;
	GElf_Shdr *shdr = &elf->shdrs[sec];

	if (!is_undef_symbol(&s->sym)) {
		GElf_Phdr *phdr, *phdrs;

		nphdrs = 0;
		phdrs = malloc(sizeof(GElf_Phdr) * elf->phdrnum);

		for (i = 0; i < elf->phdrnum; i++) {
			phdr = &elf->phdrs[i];
			if (shdr->sh_offset >= phdr->p_offset &&
				shdr->sh_offset + shdr->sh_size <=
					phdr->p_offset + phdr->p_filesz) {
				memcpy(&phdrs[nphdrs], phdr, sizeof(GElf_Phdr));
				nphdrs++;
			}
		}
		if (nphdrs) {
			s->nphdrs = nphdrs;
			s->phdrs = malloc(sizeof(GElf_Phdr) * nphdrs);
			memcpy(s->phdrs, phdrs, sizeof(GElf_Phdr) * nphdrs);
		}
		free(phdrs);
	}

	node = rb_insert_node(&elf->elf_file_symbols, &s->node,
			      cmp_symbol_name, (unsigned long)s);
	return node ? -1 : 0;
}

void free_symbol(struct symbol *s)
{
	if (s->phdrs)
		free(s->phdrs);
	free(s->name);
	free(s);
}

void rb_free_symbol(struct rb_node *node)
{
	struct symbol *s = rb_entry(node, struct symbol, node);
	free_symbol(s);
}

int fprint_symbol(FILE *fp, struct symbol *s, int firstline)
{
	return fprint_sym(fp, &s->sym, s->name, NULL, firstline);
}

