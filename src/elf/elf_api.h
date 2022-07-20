#pragma once

#include <stdint.h>
#include <libelf.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <elf/elf_struct.h>
#include <utils/util.h>
#include <utils/compiler.h>

#ifdef HAVE_JSON_C_H
#include <json-c/json.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ELF_UNIX_PATH "/tmp/_unix_elf_main"

enum cmd_type {
	CMD_MIN__,
	CMD_ELF_LOAD,	/* Load a elf file */
	CMD_ELF_DELETE,	/* Delete a elf file */
	CMD_ELF_LIST,	/* List all loaded elf file */
	CMD_ELF_SELECT,	/* Select a loaded elf file */
	CMD_ELF_GET_EHDR,	/* Get elf header */
	CMD_ELF_GET_PHDR,	/* Get elf program header */
	CMD_ELF_GET_SHDR,	/* Get elf section header */
	CMD_REGISTER_CLIENT,/* Register client information */
	CMD_LIST_CLIENT,	/* List clients information */
	CMD_TEST_SERVER,	/* Test UNIX socket is OK? */
	CMD_ELF_ACK,	/* All msg's ack */
	CMD_MAX__
};

/**
 *     cmd               data[]              data_len
 * CMD_ELF_LOAD     struct cmd_elf_file       struct
 * CMD_ELF_LIST     struct cmd_elf_empty      struct
 * CMD_ELF_SELECT   struct cmd_elf_file       struct
 * CMD_ELF_GET_EHDR struct cmd_elf_empty      struct
 * CMD_ELF_GET_PHDR struct cmd_elf_empty      struct
 * CMD_ELF_GET_SHDR struct cmd_elf_empty      struct
 * CMD_REGISTER_CLIENT  struct client_info    struct
 * CMD_LIST_CLIENT  struct cmd_elf_empty      struct
 * CMD_TEST_SERVER  struct cmd_elf_empty      struct
 * CMD_ELF_ACK      struct cmd_elf_ack        struct + data
 */
struct cmd_elf {
	enum cmd_type cmd;
	uint16_t data_len;

	unsigned int is_ack:1;
	unsigned int has_next:1;
	int reserved:14;

	/* struct cmd_elf_xxx */
	char data[];
};

struct cmd_elf_file {
#define CMD_ELF_LOAD CMD_ELF_LOAD
#define CMD_ELF_DELETE CMD_ELF_DELETE
#define CMD_ELF_SELECT CMD_ELF_SELECT
	char file[256];
};

struct cmd_elf_empty {
#define CMD_ELF_LIST CMD_ELF_LIST
#define CMD_ELF_GET_EHDR CMD_ELF_GET_EHDR
#define CMD_ELF_GET_PHDR CMD_ELF_GET_PHDR
#define CMD_ELF_GET_SHDR CMD_ELF_GET_SHDR
#define CMD_TEST_SERVER	CMD_TEST_SERVER
#define CMD_LIST_CLIENT CMD_LIST_CLIENT
};

struct cmd_elf_ack {
#define CMD_ELF_ACK CMD_ELF_ACK
	union {
		int result;
		int _errno; // /usr/include/errno.h
	};
	/**
	 * Format:
	 *  CMD_ELF_LIST:
	 *   +(uint32_t total_number)
	 *   +(uint32_t index_number, start from 1)
	 *   +(uint32_t selected, boolean, 0-not selected)
	 *   +filename\0
	 *
	 *  CMD_ELF_GET_EHDR:
	 *   +(GElf_Ehdr ehdr)
	 *
	 *  CMD_ELF_GET_PHDR:
	 *   +(uint32_t total_number)
	 *   +(uint32_t index_number, start from 1)
	 *   +(GElf_Phdr phdr)
	 *   +(1 byte)
	 *
	 *  CMD_ELF_GET_SHDR:
	 *   +(uint32_t total_number)
	 *   +(uint32_t index_number, start from 1)
	 *   +(GElf_Shdr shdr)
	 *   +(1 byte)
	 *   +shdrname\0
	 *
	 *  CMD_LIST_CLIENT:
	 *   +(uint32_t total_number)
	 *   +(uint32_t index_number, start from 1)
	 *   +(uint32_t is_me, boolean, 0-not me)
	 *   +(struct client_info)
	 *   +(1 byte)
	 *
	 *  CMD_TEST_SERVER:
	 *   +(char string[unknown length]:
	 *     format:string1\0) and obey `has_next'.
	 */
	char data[];
};

struct file_info {
	file_type type;
	const char *name;
	bool client_select;
};

struct client;

struct cmd_handler {
	enum cmd_type cmd;
	int (*handler)(struct client*, struct cmd_elf *);
	// Call send_one_ack() if ack = NULL, see handle_client_msg()
	// Call send_one_ack() manually if ack != NULL
	int (*ack)(struct client*, struct cmd_elf *);
};

enum client_type {
	CLIENT_NONE,
	CLIENT_CLI,
	CLIENT_GTK,
};

struct client_info {
#define CMD_REGISTER_CLIENT CMD_REGISTER_CLIENT
	enum client_type type;

	// Record start time
	// write: gettimeofday(&start, NULL)
	// read: strftime(buffer, 40, "%m-%d-%Y/%T", localtime(&start.tv_sec));
	struct timeval start;

	int clientfd; // = connect(2)
	int connfd; // = accept(2)
};

struct client {
	struct client_info info;
	struct sockaddr_un addr;
	/* client list node */
	struct list_head node;

	/* CMD: SELECT ELF [filepath] */
	struct elf_file *selected_elf;

	unsigned long int cmd_stat[CMD_MAX__];
};

int elf_main(int argc, char *argv[]);
void elf_exit(void);
int create_elf_client(void);
int close_elf_client(int fd);

static void __unused *cmd_data(struct cmd_elf *cmd) {
	return cmd->data;
}

static uint16_t __unused cmd_len(struct cmd_elf *cmd) {
	return cmd->data_len + sizeof(struct cmd_elf);
}

static void __unused *ack_data(struct cmd_elf_ack *ack) {
	return ack->data;
}

int send_one_ack(struct client *client, struct cmd_elf *cmd_ack);
int client_recv_acks(int connfd, int (*handler)(struct cmd_elf *msg_ack));

/* Client helper */
int client_open_elf_file(int connfd, const char *filepath);
int client_delete_elf_file(int connfd, const char *filepath);
int client_list_elf(int connfd, void (*handler)(struct file_info *info));
int client_select_elf_file(int connfd, const char *filepath);
int client_get_elf_ehdr(int connfd, int (*handler)(const GElf_Ehdr *ehdr));
int client_get_elf_phdr(int connfd, int (*handler)(const GElf_Phdr *phdr));
int client_get_elf_shdr(int connfd,
		int (*handler)(const GElf_Shdr *shdr, const char *secname));
int client_register(int connfd, enum client_type type, int (*handler)(void));
int client_list_client(int connfd,
		void (*handler)(struct nr_idx_bool *, struct client_info *info));
int client_test_server(int connfd, int (*handler)(const char *str, int len));


/* ELF Ehdr api */
int print_ehdr(const GElf_Ehdr *ehdr);
#ifdef HAVE_JSON_C_LIBRARIES
json_object *json_ehdr(const GElf_Ehdr *ehdr);
#endif
int print_json_ehdr(const GElf_Ehdr *ehdr);
const char *ei_class_string(const GElf_Ehdr *ehdr);
const char *ei_data_string(const GElf_Ehdr *ehdr);
const char *ei_osabi_string(const GElf_Ehdr *ehdr);
const char *e_type_string(const GElf_Ehdr *ehdr);
const char *e_machine_string(const GElf_Ehdr *ehdr);


/* ELF Phdr api */
int print_phdr(const GElf_Phdr *phdr);
#ifdef HAVE_JSON_C_LIBRARIES
json_object *json_phdr(const GElf_Phdr *phdr);
#endif
int print_json_phdr(const GElf_Phdr *phdr);
const char *p_type_string(const GElf_Phdr *phdr);


/* ELF Shdr api */
int print_shdr(const GElf_Shdr *shdr, const char *secname);
const char *sh_name_string(const GElf_Shdr *shdr);
const char *sh_type_string(const GElf_Shdr *shdr);
const char *sh_flags_string(const GElf_Shdr *shdr,
	void *buff, ssize_t buff_len);
#ifdef HAVE_JSON_C_LIBRARIES
json_object *json_shdr(const GElf_Shdr *shdr, const char *secname);
#endif
int print_json_shdr(const GElf_Shdr *shdr, const char *secname);

int handle_symtab(struct elf_file *elf, Elf_Scn *scn, int type);


/* ELF Rela api */
const char *rela_type_string(int r);
void print_rela(GElf_Rela *rela);


#ifdef __cplusplus
}
#endif

