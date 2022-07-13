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

#include <elf/elf_api.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>

#include "elf-usdt.h"

int test_server_handler(struct client *client, struct cmd_elf *msg_ack)
{
	return 0;
}

int test_server_handler_ack(struct client *client, struct cmd_elf *msg_ack)
{
	int total_nbytes = 0;
	uint32_t init_len = msg_ack->data_len;
	struct cmd_elf_ack *ack = cmd_data(msg_ack);

	for (;;) {
		bool has_next = true;
		// see struct cmd_elf_ack.data
		char *data = ack_data(ack);
		uint32_t add_len = 0;

		if (total_nbytes >= BUFFER_SIZE * 2) {
			msg_ack->has_next = 0;
		} else {
			msg_ack->has_next = 1;
		}

		has_next = msg_ack->has_next;

		/* Copy one section header */
		int n = sprintf(data, "(%d) Hello World%s",
			total_nbytes, has_next?";":".");
		data[n] = '\0';
		add_len += n + 1;

		msg_ack->cmd = CMD_TEST_SERVER;
		msg_ack->data_len = init_len + add_len;
		msg_ack->is_ack = 1;
		ack->result = 0;

		/* Talk to client */
		total_nbytes += send_one_ack(client, msg_ack);

		if (!has_next) break;
	}

	return 0;
}

