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
	int i;
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

	for (i = 0; i < elf->phdrnum; i++) {
		uint16_t add_len = 0;
		// see struct cmd_elf_ack.data
		char *data = ack_data(ack);
		int32_t data_left_len = BUFFER_SIZE -
				sizeof(struct cmd_elf) - sizeof(struct cmd_elf_ack);

		/* Number of ELF program header */
		data = data_add_u32(data, elf->phdrnum);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Index of this ELF program header */
		data = data_add_u32(data, i + 1);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Copy one program header */
		memcpy(data, &elf->phdrs[i], sizeof(GElf_Phdr));
		data[sizeof(GElf_Phdr)] = '\0';
		add_len += sizeof(GElf_Phdr) + 1;
		data_left_len -= sizeof(GElf_Phdr) + 1;
		data += sizeof(GElf_Phdr) + 1;

		msg_ack->cmd = CMD_ELF_GET_PHDR;
		msg_ack->data_len = init_len + add_len;
		msg_ack->is_ack = 1;
		msg_ack->has_next = (i == (elf->phdrnum - 1))?0:1;

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
	int i;
	struct elf_file *elf = client->selected_elf;
	uint32_t init_len = msg_ack->data_len;
	struct cmd_elf_ack *ack = cmd_data(msg_ack);

	if (!elf) {
		lerror("no selected elf.\n");
		char *data = ack_data(ack);
		/* No selected elf file */
		uint32_t *nr = (uint32_t *)data;
		*nr = 0;
		msg_ack->data_len += sizeof(uint32_t);

		ack->result = -ENOENT; /* No such file or directory */

		send_one_ack(client, msg_ack);
		return 0;
	}

	for (i = 0; i < elf->shdrnum; i++) {
		uint16_t add_len = 0;
		// see struct cmd_elf_ack.data
		char *data = ack_data(ack);
		int32_t data_left_len = BUFFER_SIZE -
				sizeof(struct cmd_elf) - sizeof(struct cmd_elf_ack);

		/* Number of ELF section header */
		data = data_add_u32(data, elf->shdrnum);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Index of this ELF section header */
		data = data_add_u32(data, i + 1);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Copy one section header */
		memcpy(data, &elf->shdrs[i], sizeof(GElf_Shdr));
		data[sizeof(GElf_Shdr)] = '\0';
		add_len += sizeof(GElf_Shdr) + 1;
		data_left_len -= sizeof(GElf_Shdr) + 1;
		data += sizeof(GElf_Shdr) + 1;

		/* Copy one section header name */
		strcpy(data, elf->shdrnames[i]);
		uint16_t __l = strlen(elf->shdrnames[i]);
		data[__l] = '\0';
		add_len += __l + 1;
		data_left_len -= __l + 1;
		data += __l + 1;

		msg_ack->cmd = CMD_ELF_GET_SHDR;
		msg_ack->data_len = init_len + add_len;
		msg_ack->is_ack = 1;
		msg_ack->has_next = (i == (elf->shdrnum - 1))?0:1;

		/* Talk to client */
		send_one_ack(client, msg_ack);
	}

	return 0;
}

