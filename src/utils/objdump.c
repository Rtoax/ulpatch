// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdio.h>
#include <malloc.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <elf/elf_api.h>

#include "log.h"
#include "util.h"
#include "list.h"


struct objdump_elf_file {
	char name[MAX_PATH];
	/* head is file_list */
	struct list_head node;
};

/* We just open few elf files, link list is ok. */
static LIST_HEAD(file_list);


static struct objdump_elf_file* file_already_load(const char *filename)
{
	struct objdump_elf_file *f, *tmp, *ret = NULL;

	list_for_each_entry_safe(f, tmp, &file_list, node) {
		if (!strcmp(filename, f->name)) {
			ret = f;
			break;
		}
	}

	return ret;
}

static int objdump_elf_load_plt(struct objdump_elf_file *file)
{
	FILE *fp;
	char cmd[BUFFER_SIZE], line[BUFFER_SIZE];

	/* $ objdump -d test
	 *
	 * [...]
	 *
	 * Disassembly of section .plt:
	 *
	 * 0000000000403020 <.plt>:
	 *  403020:	ff 35 e2 9f 01 00    	pushq  0x19fe2(%rip)        # 41d008 <_GLOBAL_OFFSET_TABLE_+0x8>
	 *  403026:	ff 25 e4 9f 01 00    	jmpq   *0x19fe4(%rip)        # 41d010 <_GLOBAL_OFFSET_TABLE_+0x10>
	 *  40302c:	0f 1f 40 00          	nopl   0x0(%rax)
	 *
	 * 0000000000403030 <gelf_getehdr@plt>:
	 *  403030:	ff 25 e2 9f 01 00    	jmpq   *0x19fe2(%rip)        # 41d018 <gelf_getehdr@ELFUTILS_1.0>
	 *  403036:	68 00 00 00 00       	pushq  $0x0
	 *  40303b:	e9 e0 ff ff ff       	jmpq   403020 <.plt>
	 *
	 * To get '0000000000403030 <gelf_getehdr@plt>:':
	 *
	 * $ objdump -d test | grep @plt | grep ^0
	 */
	snprintf(cmd, BUFFER_SIZE,
		"objdump -d %s | grep @plt | grep ^0", file->name);

	fp = popen(cmd, "r");

	while (1) {
		unsigned long addr;
		char sym[256];
		int ret;

		if (!fgets(line, sizeof(line), fp))
			break;

		ret = sscanf(line, "%lx %s", &addr, sym);
		if (ret <= 0) {
			lerror("sscanf failed.\n");
			continue;
		}

		/* For example:
		 * 0000000000403030 <gelf_getehdr@plt>:
		 *
		 * $addr: 0000000000403030
		 * $sym:  <gelf_getehdr@plt>:
		 */
		char *s = sym + 1;
		int slen = strlen(s);

		if (!strstr(s, "@plt>:")) {
			lerror("Wrong format: %s\n", sym);
			continue;
		}

		s[slen - strlen("@plt>:")] = '\0';

		linfo("%s: %#08lx %s\n", basename(file->name), addr, s);
	}

	pclose(fp);

	return 0;
}

static struct objdump_elf_file* file_load(const char *filename)
{
	struct objdump_elf_file *file;

	file = malloc(sizeof(struct objdump_elf_file));

	strncpy(file->name, filename, MAX_PATH - 1);

	objdump_elf_load_plt(file);

	list_add(&file->node, &file_list);

	return file;
}

struct objdump_elf_file* objdump_elf_load(const char *elf_file)
{
	struct objdump_elf_file *file = NULL;

	if (!fexist(elf_file)) {
		errno = -EEXIST;
		return NULL;
	}

	file = file_already_load(elf_file);
	if (!file) {
		file = file_load(elf_file);
	}

	return file;
}

int objdump_elf_close(struct objdump_elf_file *file)
{
	if (!file)
		return -1;

	list_del(&file->node);
	free(file);

	return 0;
}

int objdump_destroy(void)
{
	struct objdump_elf_file *f, *tmp;

	list_for_each_entry_safe(f, tmp, &file_list, node) {
		list_del(&f->node);
		free(f);
	}

	return 0;
}

