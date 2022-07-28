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
	int i;
	int ret = 0;

	for (i = 0; i < elf->shdrnum; i++) {
		GElf_Shdr *shdr = &elf->shdrs[i];
		Elf_Scn *scn = elf_getscn(elf->elf, i);

		if (gelf_getshdr(scn, shdr) == NULL) {
			lerror("gelf_getshdr failed: %s\n", elf_errmsg(-1));
			return -ENOENT;
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

		elf->shdrnames[i] =
			elf_strptr(elf->elf, elf->shdrstrndx, shdr->sh_name);

		if (elf->shdrnames[i] == NULL) {
			lerror("couldn't get section name: %s\n", elf_errmsg(-1));
			return -ENOENT;
		}

		ldebug("section name: %s, %lx\n",
			elf->shdrnames[i], shdr->sh_type, sh_type_string(shdr));

		// Handle section header by type
		switch (shdr->sh_type) {
		case SHT_SYMTAB:
			elf->symtab_data = elf_getdata(scn, NULL);
			elf->symtab_shdr_idx = i;
			break;
		case SHT_DYNSYM:
			elf->dynsym_data = elf_getdata(scn, NULL);
			elf->dynsym_shdr_idx = i;
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

static __unused struct elf_file *elf_file_load(const char *filepath)
{
	int fd, i;
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
	strncpy(elf->filepath, filepath, sizeof(elf->filepath));

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
		lerror("unsupport %d\n", ei_class_string(elf->ehdr));
		goto free_elf;
	}
	if (elf->ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
		lerror("unsupport %s\n", ei_data_string(elf->ehdr));
		goto free_elf;
	}

/* Program header */
	elf_getphdrnum(__elf, &elf->phdrnum);
	elf->phdrs = malloc(sizeof(GElf_Phdr) * elf->phdrnum);
	assert(elf->phdrs && "Malloc failed.");

	for (i = 0; i < elf->phdrnum; i++) {
		GElf_Phdr *phdr = gelf_getphdr(__elf, i, &elf->phdrs[i]);
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
		goto free_phdrs;
	}

	if (handle_sections(elf) != 0)
		goto free_shdrs;

/* Do some necessary check */

	/* Elf MUST has Build ID */
	if (!elf->build_id) {
		if (elf->ehdr->e_type == ET_REL) {
			elf->build_id = "REL no Build ID";
		} else {
			lerror("No Build ID found in %s,%s, check with 'readelf -n'\n",
				elf->filepath, e_type_string(elf->ehdr));
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

static __unused int
elf_file_delete(struct client *client, const char *filepath)
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

	close(elf->fd);
	list_del(&elf->node);
	elf_files_number--;

	struct client *clt;
	list_for_each_entry(clt, &client_list, node) {
		if (clt->selected_elf == elf) {
			clt->selected_elf = NULL;
		}
	}

	elf_end(elf->elf);
	free(elf);

	return 0;
}

int elf_load_handler(struct client *client, struct cmd_elf *cmd)
{
	struct cmd_elf_file *load = cmd_data(cmd);
	struct elf_file __unused *elf = elf_file_load(load->file);

	return elf?0:-ENOENT;
}

int elf_delete_handler(struct client *client, struct cmd_elf *cmd)
{
	struct cmd_elf_file *load = cmd_data(cmd);

	return elf_file_delete(client, load->file);
}

int elf_list_handler(struct client *client, struct cmd_elf *cmd)
{
	return 0;
}

int elf_list_handler_ack(struct client *client, struct cmd_elf *msg_ack)
{
	struct elf_file *elf = NULL;

	uint32_t count = 0;
	uint32_t init_len = msg_ack->data_len;
	struct cmd_elf_ack *ack = cmd_data(msg_ack);

	/* No elf loaded, return */
	if (elf_files_number <= 0) {
		char *data = ack_data(ack);
		/* Number of ELF files */
		data_add_u32(data, elf_files_number);
		msg_ack->data_len += sizeof(uint32_t);
		send_one_ack(client, msg_ack);
		return 0;
	}

	list_for_each_entry(elf, &elf_file_list, node) {
		uint16_t add_len = 0;
		// see struct cmd_elf_ack.data
		char *data = ack_data(ack);
		int32_t data_left_len = BUFFER_SIZE -
				sizeof(struct cmd_elf) - sizeof(struct cmd_elf_ack);

		/* Number of ELF files */
		data = data_add_u32(data, elf_files_number);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Index of ELF files */
		data = data_add_u32(data, ++count);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* This client selected? */
		// 0 - not select, see struct cmd_elf_ack.data
		data = data_add_u32(data, (client->selected_elf == elf)?1:0);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		uint32_t len = data_add_string((void**)&data, elf->filepath);
		if (data_left_len < len) {
			lerror("no space left on buffer.\n");
			break;
		}

		add_len += len + 1;
		data_left_len -= len + 1;

		// Build ID
		len = data_add_string((void**)&data, elf->build_id);
		if (data_left_len < len) {
			lerror("no space left on buffer.\n");
			break;
		}

		add_len += len + 1;
		data_left_len -= len + 1;

		if (data_left_len < 0) {
			lerror("File name too long, %s\n", elf->filepath);
			return -EINVAL; /* Invalid argument */
		}

		msg_ack->cmd = CMD_ELF_LIST;
		msg_ack->data_len = init_len + add_len;
		msg_ack->is_ack = 1;
		msg_ack->has_next = (count == elf_files_number)?0:1;

		send_one_ack(client, msg_ack);
	}

	return 0;
}

int elf_select_handler(struct client *client, struct cmd_elf *cmd)
{
	struct cmd_elf_file *select = cmd_data(cmd);
	struct elf_file *elf = NULL;

	list_for_each_entry(elf, &elf_file_list, node) {
		if (!strcmp(select->file, elf->filepath)) {
			ldebug("select elf: %s\n", elf->filepath);
			client->selected_elf = elf;
			return 0;
		}
	}
	return -ENOENT; /* No such file or directory */
}
