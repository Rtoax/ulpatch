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
#include <sys/time.h>

#include <elf/elf_api.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>

int create_elf_client(void)
{
	int connect_fd, ret = -1;
	struct sockaddr_un srv_addr;

	connect_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (connect_fd < 0) {
		lerror("create socket error: %s\n", strerror(errno));
		return -EINVAL;
	}

	srv_addr.sun_family = AF_UNIX;
	strcpy(srv_addr.sun_path, ELF_UNIX_PATH);

	ret = connect(connect_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (ret == -1) {
		lerror("connect error: %s, %s\n", strerror(errno), ELF_UNIX_PATH);
		close(connect_fd);
		exit(1);
	}
	return connect_fd;
}

int close_elf_client(int fd)
{
	return close(fd);
}

static int
__client_elf_file(int connfd, enum cmd_type cmdType, const char *filepath)
{
	char buffer[BUFFER_SIZE] = {};
	struct cmd_elf *cmd = (struct cmd_elf *)buffer;
	struct cmd_elf_file *elf_load;

	cmd->cmd = cmdType;
	cmd->is_ack = 0;
	cmd->has_next = 0;
	cmd->data_len = sizeof(struct cmd_elf_file);
	elf_load = cmd_data(cmd);

	// absolute path
	if (filepath[0] == '/') {
		strncpy(elf_load->file, filepath, sizeof(elf_load->file) - 1);
	// relative path, need swap to absolute path
	} else {
		char *pwd = get_current_dir_name();
		assert(pwd && "NULL pwd");
		snprintf(elf_load->file, sizeof(elf_load->file), "%s/%s",
			pwd, filepath);
	}

	write(connfd, cmd, cmd_len(cmd));

	int ack_handler(struct cmd_elf *msg_ack) {

		struct cmd_elf_ack *ack = cmd_data(msg_ack);
		return ack->result;
	}

	return client_recv_acks(connfd, ack_handler);
}

int client_open_elf_file(int connfd, const char *filepath)
{
	return __client_elf_file(connfd, CMD_ELF_LOAD, filepath);
}

int client_delete_elf_file(int connfd, const char *filepath)
{
	return __client_elf_file(connfd, CMD_ELF_DELETE, filepath);
}

int client_select_elf_file(int connfd, const char *filepath)
{
	return __client_elf_file(connfd, CMD_ELF_SELECT, filepath);
}

int client_list_elf(int connfd, void (*handler)(struct file_info *info))
{
	assert(handler && "must have handler()");

	struct cmd_elf cmd = {
		.cmd = CMD_ELF_LIST,
		.is_ack = 0,
		.has_next = 0,
		.data_len = sizeof(struct cmd_elf_empty),
	};
	write(connfd, &cmd, cmd_len(&cmd));

	int ack_handler(struct cmd_elf *msg_ack) {

		char *data = ack_data(cmd_data(msg_ack));

		uint32_t __unused nr_elf = data_get_u32((void **)&data);
		if (nr_elf == 0) {
			printf("No ELF Loaded.\n");
			return 0;
		}
		uint32_t __unused idx_elf = data_get_u32((void **)&data);
		uint32_t selected = data_get_u32((void **)&data);

		struct file_info info = {
			.type = FILE_ELF,
			.name = data,
			.client_select = selected?true:false,
			.elf_build_id = data + strlen(data) + 1,
		};

		handler(&info);

		return 0;
	}

	client_recv_acks(connfd, ack_handler);

	return 0;
}

int client_get_elf_ehdr(int connfd, int (*handler)(const GElf_Ehdr *ehdr))
{
	assert(handler && "must have handler()");

	struct cmd_elf cmd = {
		.cmd = CMD_ELF_GET_EHDR,
		.is_ack = 0,
		.has_next = 0,
		.data_len = sizeof(struct cmd_elf_empty),
	};
	write(connfd, &cmd, cmd_len(&cmd));

	int ack_handler(struct cmd_elf *msg_ack) {
		struct cmd_elf_ack *ack = cmd_data(msg_ack);
		if (ack->result == -ENOENT) {
			printf("No Selected ELF.\n");
			return ack->result;
		}

		GElf_Ehdr *ehdr = ack_data(ack);
		return handler(ehdr);
	}

	return client_recv_acks(connfd, ack_handler);
}

int client_get_elf_phdr(int connfd, int (*handler)(const GElf_Phdr *phdr))
{
	assert(handler && "must have handler()");

	struct cmd_elf cmd = {
		.cmd = CMD_ELF_GET_PHDR,
		.is_ack = 0,
		.has_next = 0,
		.data_len = sizeof(struct cmd_elf_empty),
	};
	write(connfd, &cmd, cmd_len(&cmd));

	int ack_handler(struct cmd_elf *msg_ack) {
		GElf_Phdr *phdr = NULL;

		struct cmd_elf_ack *ack = cmd_data(msg_ack);

		char *data = ack_data(ack);

		uint32_t __unused nr_phdr = data_get_u32((void **)&data);
		if (nr_phdr == 0) {
			printf("No ELF Selected or ELF no Program Header at all.\n");
			return ack->result;
		}

		uint32_t __unused idx_phdr = data_get_u32((void **)&data);

		phdr = (GElf_Phdr *)data;
		return handler(phdr);
	}

	return client_recv_acks(connfd, ack_handler);
}

int client_get_elf_shdr(int connfd,
		int (*handler)(const GElf_Shdr *shdr, const char *secname))
{
	assert(handler && "must have handler()");

	struct cmd_elf cmd = {
		.cmd = CMD_ELF_GET_SHDR,
		.is_ack = 0,
		.has_next = 0,
		.data_len = sizeof(struct cmd_elf_empty),
	};
	write(connfd, &cmd, cmd_len(&cmd));

	int ack_handler(struct cmd_elf *msg_ack) {
		GElf_Shdr *shdr = NULL;
		struct cmd_elf_ack *ack = cmd_data(msg_ack);

		char *data = ack_data(ack);
		uint32_t __unused nr_shdrs = data_get_u32((void **)&data);
		if (nr_shdrs == 0) {
			printf("No ELF Selected or ELF no Section at all.\n");
			return ack->result;
		}
		uint32_t __unused idx_shdr = data_get_u32((void **)&data);

		shdr = (GElf_Shdr *)data;

		data += sizeof(GElf_Shdr);

		char *secname = data + 1;

		return handler(shdr, secname);
	}

	return client_recv_acks(connfd, ack_handler);
}

int client_get_elf_syms(int connfd,
	int (*handler)(const GElf_Sym *sym, const char *symname,
		const char *vername))
{
	assert(handler && "must have handler()");

	struct cmd_elf cmd = {
		.cmd = CMD_ELF_GET_SYMS,
		.is_ack = 0,
		.has_next = 0,
		.data_len = sizeof(struct cmd_elf_empty),
	};
	write(connfd, &cmd, cmd_len(&cmd));

	int ack_handler(struct cmd_elf *msg_ack) {
		GElf_Sym *sym = NULL;
		struct cmd_elf_ack *ack = cmd_data(msg_ack);

		char *data = ack_data(ack);
		uint32_t __unused nr_syms = data_get_u32((void **)&data);
		if (nr_syms == 0) {
			printf("No ELF Selected or ELF no Symbol at all.\n");
			return ack->result;
		}
		uint32_t __unused idx_sym = data_get_u32((void **)&data);

		sym = (GElf_Sym *)data;

		data += sizeof(GElf_Sym) + 1;

		char *symname = data;

		return handler(sym, symname, data + strlen(symname)+1);
	}

	return client_recv_acks(connfd, ack_handler);
}

int register_client_handler(struct client *client, struct cmd_elf *cmd)
{
	struct client_info *info = cmd_data(cmd);

	struct client_info *dst_info = &client->info;
	int serverfd = dst_info->connfd;

	*dst_info = *info;

	dst_info->connfd = serverfd;

	return 0;
}

int client_register(int connfd, enum client_type type, int (*handler)(void))
{
	assert(handler && "must have handler()");

	char buffer[BUFFER_SIZE] = {};
	struct cmd_elf *cmd = (struct cmd_elf *)buffer;

	cmd->cmd = CMD_REGISTER_CLIENT;
	cmd->is_ack = 0;
	cmd->has_next = 0;
	cmd->data_len = sizeof(struct client_info);

	struct client_info *info = cmd_data(cmd);

	info->type = type;
	info->clientfd = connfd;
	gettimeofday(&info->start, NULL);

	write(connfd, cmd, cmd_len(cmd));

	int ack_handler(struct cmd_elf *msg_ack) {
		return handler();
	}

	client_recv_acks(connfd, ack_handler);

	return 0;
}

int client_list_client(int connfd,
		void (*handler)(struct nr_idx_bool *nib, struct client_info *info))
{
	assert(handler && "must have handler()");

	struct cmd_elf cmd = {
		.cmd = CMD_LIST_CLIENT,
		.is_ack = 0,
		.has_next = 0,
		.data_len = sizeof(struct cmd_elf_empty),
	};
	write(connfd, &cmd, cmd_len(&cmd));

	int ack_handler(struct cmd_elf *msg_ack) {

		char *data = ack_data(cmd_data(msg_ack));

		uint32_t __unused nr_clis = data_get_u32((void **)&data);
		if (nr_clis == 0) {
			printf("No client connected.\n");
			return 0;
		}
		uint32_t __unused idx = data_get_u32((void **)&data);
		uint32_t __unused is_me = data_get_u32((void **)&data);

		struct nr_idx_bool nib = {
			.nr = nr_clis,
			.idx = idx,
			.is = is_me,
		};

		struct client_info *info = (void *)data;
		handler(&nib, info);

		return 0;
	}

	client_recv_acks(connfd, ack_handler);

	return 0;
}

int list_client_handler(struct client *client, struct cmd_elf *cmd)
{
	return 0;
}

int list_client_handler_ack(struct client *client, struct cmd_elf *msg_ack)
{
	struct client *iclient = NULL;

	uint32_t count = 0;
	uint32_t init_len = msg_ack->data_len;
	struct cmd_elf_ack *ack = cmd_data(msg_ack);

	/* No elf loaded, return */
	if (nr_clients <= 0) {
		char *data = ack_data(ack);
		/* Number of clients */
		data = data_add_u32(data, nr_clients);
		msg_ack->data_len += sizeof(uint32_t);
		send_one_ack(client, msg_ack);
		return 0;
	}

	list_for_each_entry(iclient, &client_list, node) {
		uint16_t add_len = 0;
		// see struct cmd_elf_ack.data
		char *data = ack_data(ack);
		int32_t data_left_len = BUFFER_SIZE -
				sizeof(struct cmd_elf) - sizeof(struct cmd_elf_ack);

		/* Number of Clients */
		data = data_add_u32(data, nr_clients);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* Index of client */
		data = data_add_u32(data, ++count);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		/* It's me? */
		// 0 - isn't me
		data = data_add_u32(data, (client == iclient)?1:0);
		add_len += sizeof(uint32_t);
		data_left_len -= sizeof(uint32_t);

		uint16_t len = sizeof(struct client_info);
		if (data_left_len < len + 1) {
			lerror("no space left on buffer.\n");
			break;
		}

		memcpy(data, &iclient->info, len);
		data[len] = '\0';
		add_len += len + 1;
		data_left_len -= len + 1;
		data += len + 1;

		if (data_left_len < 0) {
			lerror("struct client_info too long\n");
			return -EINVAL; /* Invalid argument */
		}

		msg_ack->cmd = CMD_LIST_CLIENT;
		msg_ack->data_len = init_len + add_len;
		msg_ack->is_ack = 1;
		msg_ack->has_next = (count == nr_clients)?0:1;

		send_one_ack(client, msg_ack);
	}

	return 0;
}

int client_test_server(int connfd, int (*handler)(const char *str, int str_len))
{
	assert(handler && "must have handler()");

	struct cmd_elf cmd = {
		.cmd = CMD_TEST_SERVER,
		.is_ack = 0,
		.has_next = 0,
		.data_len = sizeof(struct cmd_elf_empty),
	};

	write(connfd, &cmd, cmd_len(&cmd));

	int ack_handler(struct cmd_elf *msg_ack) {
		char *s = ack_data(cmd_data(msg_ack));

		return handler(s, strlen(s));
	}

	client_recv_acks(connfd, ack_handler);

	return 0;
}

