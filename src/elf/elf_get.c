#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <elf/elf_api.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>


int elf_get_ehdr_handler(struct client *client, struct cmd_elf *msg_ack)
{
	return 0;
}

int elf_get_ehdr_handler_ack(struct client *client, struct cmd_elf *msg_ack)
{
	struct elf_file *elf = client->selected_elf;

	if (!elf) {
		lerror("no selected elf.\n");
		struct cmd_elf_ack *ack = cmd_data(msg_ack);
		ack->result = -ENOENT; /* No such file or directory */
		send_one_ack(client, msg_ack);
		return 0;
	}

	char *data = ack_data(cmd_data(msg_ack));

	memcpy(data, elf->ehdr, sizeof(GElf_Ehdr));

	msg_ack->cmd = CMD_ELF_GET_EHDR;
	msg_ack->data_len += sizeof(GElf_Ehdr);
	msg_ack->is_ack = 1;
	msg_ack->has_next = 0;

	send_one_ack(client, msg_ack);

	return 0;
}

int elf_get_phdr_handler(struct client *client, struct cmd_elf *msg_ack)
{
	return 0;
}

int elf_get_phdr_handler_ack(struct client *client, struct cmd_elf *msg_ack)
{
	struct elf_file *elf = client->selected_elf;
	uint32_t init_len = msg_ack->data_len;
	struct cmd_elf_ack *ack = cmd_data(msg_ack);
	struct elf_iter iter;

	if (!elf) {
		lerror("no selected elf.\n");
		char *data = ack_data(ack);
		/* No selected elf file */
		data_add_u32(data, 0);
		msg_ack->data_len += sizeof(uint32_t);

		ack->result = -ENOENT; /* No such file or directory */

		send_one_ack(client, msg_ack);
		return 0;
	}

	elf_for_each_phdr(elf, &iter) {

		uint16_t add_len = 0;
		// see struct cmd_elf_ack.data
		char *data = ack_data(ack);
		int32_t data_left_len = BUFFER_SIZE -
				sizeof(struct cmd_elf) - sizeof(struct cmd_elf_ack);

		/* Number of ELF program header */
		data = data_add_u32(data, iter.nr);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Index of this ELF program header */
		data = data_add_u32(data, iter.i + 1);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Copy one program header */
		memcpy(data, iter.phdr, sizeof(GElf_Phdr));
		data[sizeof(GElf_Phdr)] = '\0';
		add_len += sizeof(GElf_Phdr) + 1;
		data_left_len -= sizeof(GElf_Phdr) + 1;
		data += sizeof(GElf_Phdr) + 1;

		msg_ack->cmd = CMD_ELF_GET_PHDR;
		msg_ack->data_len = init_len + add_len;
		msg_ack->is_ack = 1;
		msg_ack->has_next = (iter.i == (iter.nr - 1))?0:1;

		/* Talk to client */
		send_one_ack(client, msg_ack);
	}

	return 0;
}

int elf_get_shdr_handler(struct client *client, struct cmd_elf *msg_ack)
{
	return 0;
}

int elf_get_shdr_handler_ack(struct client *client, struct cmd_elf *msg_ack)
{
	struct elf_file *elf = client->selected_elf;
	uint32_t init_len = msg_ack->data_len;
	struct cmd_elf_ack *ack = cmd_data(msg_ack);

	struct elf_iter iter;

	if (!elf) {
		lerror("no selected elf.\n");
		char *data = ack_data(ack);
		/* No selected elf file */
		data_add_u32(data, 0);
		msg_ack->data_len += sizeof(uint32_t);

		ack->result = -ENOENT; /* No such file or directory */

		send_one_ack(client, msg_ack);
		return 0;
	}

	elf_for_each_shdr(elf, &iter) {

		uint16_t add_len = 0;
		// see struct cmd_elf_ack.data
		char *data = ack_data(ack);
		int32_t data_left_len = BUFFER_SIZE -
				sizeof(struct cmd_elf) - sizeof(struct cmd_elf_ack);

		/* Number of ELF section header */
		data = data_add_u32(data, iter.nr);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Index of this ELF section header */
		data = data_add_u32(data, iter.i + 1);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Copy one section header */
		memcpy(data, iter.shdr, sizeof(GElf_Shdr));
		data[sizeof(GElf_Shdr)] = '\0';
		add_len += sizeof(GElf_Shdr) + 1;
		data_left_len -= sizeof(GElf_Shdr) + 1;
		data += sizeof(GElf_Shdr) + 1;

		/* Copy one section header name */
		uint32_t __l = data_add_string((void**)&data, elf->shdrnames[iter.i]);
		add_len += __l;
		data_left_len -= __l;

		msg_ack->cmd = CMD_ELF_GET_SHDR;
		msg_ack->data_len = init_len + add_len;
		msg_ack->is_ack = 1;
		msg_ack->has_next = (iter.i == (iter.nr - 1))?0:1;

		/* Talk to client */
		send_one_ack(client, msg_ack);
	}

	return 0;
}

int elf_get_syms_handler(struct client *client, struct cmd_elf *msg_ack)
{
	return 0;
}

static void handle_get_symtab(struct client *client, struct cmd_elf *msg_ack,
	struct elf_file *elf, Elf_Scn *scn, uint32_t init_len)
{
	size_t nsym = 0, isym = 0;
	GElf_Sym __unused *sym, sym_mem;
	char *symname, *pversion;
	struct cmd_elf_ack *ack = cmd_data(msg_ack);

	for_each_symbol(elf, scn, sym, sym_mem, isym, nsym, symname, pversion) {

		if (!sym) continue;

		// ldebug("%s%s%s\n", symname, pversion?"@":"", pversion?:"");

		uint16_t add_len = 0;
		// see struct cmd_elf_ack.data
		char *data = ack_data(ack);
		int32_t data_left_len = BUFFER_SIZE -
				sizeof(struct cmd_elf) - sizeof(struct cmd_elf_ack);

		/* Number of ELF symbols */
		data = data_add_u32(data, elf->shdrnum);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Index of this ELF sym */
		data = data_add_u32(data, isym + 1);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Copy one Sym */
		memcpy(data, sym, sizeof(GElf_Sym));
		data[sizeof(GElf_Sym)] = '\0';
		add_len += sizeof(GElf_Sym) + 1;
		data_left_len -= sizeof(GElf_Sym) + 1;
		data += sizeof(GElf_Sym) + 1;

		/* Copy one symbol name */
		uint32_t __l = data_add_string((void**)&data, symname);
		add_len += __l;
		data_left_len -= __l;

		/* Copy one symbol GNU version name */
		__l = data_add_string((void**)&data, pversion?:"Unknown");
		add_len += __l;
		data_left_len -= __l;

		msg_ack->cmd = CMD_ELF_GET_SHDR;
		msg_ack->data_len = init_len + add_len;
		msg_ack->is_ack = 1;
		msg_ack->has_next = (isym == (nsym - 1))?0:1;

		/* Talk to client */
		send_one_ack(client, msg_ack);
	}
}

int elf_get_syms_handler_ack(struct client *client, struct cmd_elf *msg_ack)
{
	struct elf_file *elf = client->selected_elf;
	uint32_t init_len = msg_ack->data_len;
	struct cmd_elf_ack *ack = cmd_data(msg_ack);

	if (!elf) {
		lerror("no selected elf.\n");
		char *data = ack_data(ack);
		/* No selected elf file */
		data_add_u32(data, 0);
		msg_ack->data_len += sizeof(uint32_t);

		ack->result = -ENOENT; /* No such file or directory */

		send_one_ack(client, msg_ack);
		return 0;
	}

	if (elf->symtab_shdr_idx)
		handle_get_symtab(client, msg_ack, elf,
			elf_getscn(elf->elf, elf->symtab_shdr_idx), init_len);

	if (elf->dynsym_shdr_idx)
		handle_get_symtab(client, msg_ack, elf,
			elf_getscn(elf->elf, elf->dynsym_shdr_idx), init_len);

	return 0;
}

