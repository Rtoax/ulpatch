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
	char buffer[BUFFER_SIZE];
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

		uint32_t __unused nr_elf = *(uint32_t *)data;
		if (nr_elf == 0) {
			printf("No ELF Loaded.\n");
			return 0;
		}
		data += sizeof(uint32_t);
		uint32_t __unused idx_elf = *(uint32_t *)data;
		data += sizeof(uint32_t);
		uint32_t selected = *(uint32_t *)data;
		data += sizeof(uint32_t);

		struct file_info info = {
			.type = FILE_ELF,
			.name = data,
			.client_select = selected?true:false,
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

		uint32_t __unused nr_phdrs = *(uint32_t *)data;
		if (nr_phdrs == 0) {
			printf("No ELF Selected or ELF no Program Header at all.\n");
			return ack->result;
		}
		data += sizeof(uint32_t);

		uint32_t __unused idx_phdr = *(uint32_t *)data;
		data += sizeof(uint32_t);

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
		uint32_t __unused nr_shdrs = *(uint32_t *)data;
		if (nr_shdrs == 0) {
			printf("No ELF Selected or ELF no Section at all.\n");
			return ack->result;
		}
		data += sizeof(uint32_t);
		uint32_t __unused idx_shdr = *(uint32_t *)data;
		data += sizeof(uint32_t);

		shdr = (GElf_Shdr *)data;

		data += sizeof(GElf_Shdr);

		char *secname = data + 1;

		return handler(shdr, secname);
	}

	return client_recv_acks(connfd, ack_handler);
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

