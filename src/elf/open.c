// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>

static uint16_t elf_files_number = 0;
static LIST_HEAD(elf_file_list);


static __unused int handle_sections(struct elf_file *elf)
{
	int ret = 0;

	struct elf_iter iter;

	elf_for_each_shdr(elf, &iter) {

		GElf_Shdr *shdr = iter.shdr;
		Elf_Scn *scn = iter.scn;

		elf->shdrnames[iter.i] =
			elf_strptr(elf->elf, elf->shdrstrndx, shdr->sh_name);

		if (elf->shdrnames[iter.i] == NULL) {
			lerror("couldn't get section name: %s\n", elf_errmsg(-1));
			return -ENOENT;
		}

		// Handle section header by type
		switch (shdr->sh_type) {
		case SHT_SYMTAB:
			elf->symtab_data = elf_getdata(scn, NULL);
			elf->symtab_shdr_idx = iter.i;
			break;
		case SHT_DYNSYM:
			elf->dynsym_data = elf_getdata(scn, NULL);
			elf->dynsym_shdr_idx = iter.i;
			break;
		case SHT_NOTE:
			handle_notes(elf, shdr, scn);
			break;
		case SHT_REL:
		case SHT_RELA:
			if ((ret = handle_relocs(elf, shdr, scn)) != 0) {
				return ret;
			}
			break;
		case SHT_GNU_ATTRIBUTES:
		case SHT_GNU_LIBLIST:
		// readelf --section-groups
		case SHT_GROUP:
		default:
			break;
		}

		/* Find out whether we have other sections we might need.  */
		Elf_Scn *runscn = NULL;

		while ((runscn = elf_nextscn(elf->elf, runscn)) != NULL) {

			GElf_Shdr runshdr_mem;
			GElf_Shdr *runshdr = gelf_getshdr(runscn, &runshdr_mem);

			if (!runshdr) continue;

			// Handle section header by type
			switch (runshdr->sh_type) {

			/* Bingo, found the version information.  Now get the data.  */
			case SHT_GNU_versym: // .gnu.version
				if (runshdr->sh_link == elf_ndxscn(scn)) {
					elf->versym_data = elf_getdata(runscn, NULL);
				}
				break;
			/* This is the information about the needed versions.  */
			case SHT_GNU_verneed: // .gnu.version_r
				elf->verneed_data = elf_getdata(runscn, NULL);
				elf->verneed_stridx = runshdr->sh_link;
				break;
			/* This is the information about the defined versions.  */
			case SHT_GNU_verdef:
				elf->verdef_data = elf_getdata(runscn, NULL);
				elf->verdef_stridx = runshdr->sh_link;
				break;
			/* Extended section index.  */
			case SHT_SYMTAB_SHNDX:
				if (runshdr->sh_link == elf_ndxscn(scn)) {
					elf->xndx_data = elf_getdata(runscn, NULL);
				}
				break;
			}
		}
	}

	if (elf->symtab_shdr_idx)
		handle_symtab(elf, elf_getscn(elf->elf, elf->symtab_shdr_idx));

	if (elf->dynsym_shdr_idx)
		handle_symtab(elf, elf_getscn(elf->elf, elf->dynsym_shdr_idx));

	return ret;
}

struct elf_file *elf_file_open(const char *filepath)
{
	int fd;
	size_t size;
	struct elf_file *elf = NULL;
	struct elf_iter iter;

	/* Already open */
	list_for_each_entry(elf, &elf_file_list, node) {
		if (!strcmp(filepath, elf->filepath)) {
			lwarning("%s already opened.\n", filepath);
			return elf;
		}
	}
	elf = NULL;

	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		lerror("open failed: %s\n", filepath);
		goto error_open;
	}
	elf_version(EV_CURRENT);

	Elf *__elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!__elf) {
		lerror("open %s: %s\n", filepath, elf_errmsg(elf_errno()));
		goto error_elf;
	}

	char *ident = elf_getident(__elf, &size);
	if (!ident || !strcmp(ident, ELFMAG)) {
		lerror("%s is not ELF file\n", filepath);
		goto close_elf;
	}

	elf = malloc(sizeof(*elf));
	assert(elf && "Malloc failed.");

	memset(elf, 0x0, sizeof(*elf));

	elf->fd = fd;
	elf->elf = __elf;
	elf->rawfile = elf_rawfile(__elf, &elf->rawsize);
	elf->size = size;
	strncpy(elf->filepath, filepath, sizeof(elf->filepath) - 1);

	/* Init symbols red black tree
	 */
	rb_init(&elf->symbols);


/* ELF file header */
	elf->ehdr = malloc(sizeof(GElf_Ehdr));
	assert(elf->ehdr && "Malloc failed.");
	elf->ehdr = gelf_getehdr(__elf, elf->ehdr);
	/* ET_REL, ET_EXEC, ET_DYN, ET_CORE */
	if (elf->ehdr->e_type == ET_NONE) {
		lerror("unknown elf type %d\n", elf->ehdr->e_type);
		goto free_elf;
	}
	/* EM_386, EM_MIPS, EM_X86_64, EM_AARCH64, EM_BPF ... */
	if (elf->ehdr->e_machine == EM_NONE) {
		lerror("unknown elf machine %d\n", elf->ehdr->e_machine);
		goto free_elf;
	}
	if (elf->ehdr->e_version != EV_CURRENT) {
		lerror("unknown elf version %d\n", elf->ehdr->e_version);
		goto free_elf;
	}
	if (elf->ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		lerror("unsupport %d\n", elf->ehdr->e_ident[EI_CLASS]);
		goto free_elf;
	}
	if (elf->ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
		lerror("unsupport %d\n", elf->ehdr->e_ident[EI_DATA]);
		goto free_elf;
	}

/* Program header */
	elf_getphdrnum(__elf, &elf->phdrnum);
	elf->phdrs = malloc(sizeof(GElf_Phdr) * elf->phdrnum);
	assert(elf->phdrs && "Malloc failed.");

	elf_for_each_phdr(elf, &iter) {
		GElf_Phdr *phdr = gelf_getphdr(__elf, iter.i, iter.phdr);
		if (unlikely(phdr == NULL)) {
			lerror("NULL phdr.\n");
		}
	}

	if (handle_phdrs(elf) != 0)
		goto free_phdrs;

/* Section header */
	elf_getshdrnum(__elf, &elf->shdrnum);
	elf->shdrs = malloc(sizeof(GElf_Shdr) * elf->shdrnum);
	assert(elf->shdrs && "Malloc failed.");
	elf->shdrnames = malloc(sizeof(char*) * elf->shdrnum);
	assert(elf->shdrnames && "Malloc failed.");

	if (elf_getshdrstrndx(__elf, &elf->shdrstrndx) < 0) {
		lerror("cannot get section header string table index %s\n",
			elf_errmsg(-1));
		goto free_shdrs;
	}

	elf_for_each_shdr(elf, &iter) {

		GElf_Shdr *shdr = iter.shdr;
		Elf_Scn *scn = iter.scn;

		if (gelf_getshdr(scn, shdr) == NULL) {
			lerror("gelf_getshdr failed: %s\n", elf_errmsg(-1));
			goto free_shdrs;
		}

		if ((shdr->sh_flags & SHF_COMPRESSED) != 0) {

			if (elf_compress (scn, 0, 0) < 0)
				lwarning("WARNING: %s [%zd]\n",
					"Couldn't uncompress section",
					elf_ndxscn(scn));

			GElf_Shdr shdr_mem;
			shdr = gelf_getshdr(scn, &shdr_mem);

			if (unlikely (shdr == NULL)) {
				lerror("cannot get section [%zd] header: %s",
					elf_ndxscn(scn), elf_errmsg (-1));

				continue;
			}
		}
	}

	if (handle_sections(elf) != 0)
		goto free_shdrs;

/* Do some necessary check */

	/* Elf MUST has Build ID */
	if (!elf->build_id) {
		if (elf->ehdr->e_type == ET_REL) {
			elf->build_id = "REL no Build ID";
		} else {
			lerror("No Build ID found in %s,%d, check with 'readelf -n'\n",
				elf->filepath, elf->ehdr->e_type);
			goto free_shdrs;
		}
	}

/* All successful */

	/* Save it to ELF list */
	list_add(&elf->node, &elf_file_list);
	elf_files_number++;

	return elf;

free_shdrs:
	free(elf->shdrnames);
	free(elf->shdrs);
	if (elf->build_id)
		free(elf->build_id);
free_phdrs:
	free(elf->phdrs);
free_elf:
	free(elf->ehdr);
	free(elf);
close_elf:
	elf_end(__elf);
error_elf:
	close(fd);
error_open:
	return NULL;
}


static void rb_free_symbol(struct rb_node *node) {
	struct symbol *s = rb_entry(node, struct symbol, node);
	free_symbol(s);
}

int elf_file_close(const char *filepath)
{
	struct elf_file *elf = NULL, *tmp;

	/* No elf loaded, return */
	if (elf_files_number <= 0)
		return -ENOENT;

	list_for_each_entry(tmp, &elf_file_list, node) {
		if (!strcmp(tmp->filepath, filepath)) {
			elf = tmp;
			break;
		}
	}
	if (!elf) return -ENOENT;

	if (elf->build_id)
		free(elf->build_id);
	free(elf->shdrnames);
	free(elf->shdrs);
	free(elf->phdrs);
	free(elf->ehdr);

	/* Destroy symbols rb tree */
	rb_destroy(&elf->symbols, rb_free_symbol);

	close(elf->fd);
	list_del(&elf->node);
	elf_files_number--;

	elf_end(elf->elf);
	free(elf);

	return 0;
}

