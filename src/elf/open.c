// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
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


struct elf_file *elf_file_open(const char *filepath)
{
	int i, fd;
	size_t size;
	struct elf_file *elf = NULL;

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

	/* Init symbols red black tree */
	rb_init(&elf->symbols);

	/* ELF file header */

	elf->ehdr = malloc(sizeof(GElf_Ehdr));
	assert(elf->ehdr && "Malloc failed.");
	elf->ehdr = gelf_getehdr(__elf, elf->ehdr);
	if (!ehdr_ok(elf->ehdr)) {
		lerror("unsupport %d\n", elf->ehdr->e_ident[EI_DATA]);
		goto free_elf;
	}

	/* Program header */

	elf_getphdrnum(__elf, &elf->phdrnum);
	elf->phdrs = malloc(sizeof(GElf_Phdr) * elf->phdrnum);
	assert(elf->phdrs && "Malloc failed.");

	/* Load program headers */
	for (i = 0; i < elf->phdrnum; i++)
		gelf_getphdr(__elf, i, &elf->phdrs[i]);

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

	for (i = 0; i < elf->shdrnum; i++) {
		GElf_Shdr *shdr = &elf->shdrs[i];
		Elf_Scn *scn = elf_getscn(elf->elf, i);

		if (gelf_getshdr(scn, shdr) == NULL) {
			lerror("gelf_getshdr failed: %s\n", elf_errmsg(-1));
			goto free_shdrs;
		}

		if ((shdr->sh_flags & SHF_COMPRESSED) != 0) {

			if (elf_compress(scn, 0, 0) < 0)
				lwarning("WARNING: %s [%zd]\n",
					 "Couldn't uncompress section",
					 elf_ndxscn(scn));

			GElf_Shdr shdr_mem;
			shdr = gelf_getshdr(scn, &shdr_mem);

			if (unlikely(shdr == NULL)) {
				lerror("cannot get section [%zd] header: %s",
					elf_ndxscn(scn), elf_errmsg(-1));
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

	if (!elf)
		return -ENOENT;

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

