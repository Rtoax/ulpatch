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
#include <utils/task.h>
#include <utils/compiler.h>

#include "patch.h"


// see linux:kernel/module.c
static int parse_load_info(const char *obj_file, struct load_info *info)
{
	int err = 0;

	if (!fexist(obj_file)) {
		return -EEXIST;
	}

	info->len = fsize(obj_file);
	if (info->len < sizeof(*(info->hdr))) {
		return -ENOEXEC;
	}

	/* malloc a object file memory */
	info->hdr = malloc(info->len);

	/* copy from file */
	if (copy_chunked_from_file(info->hdr, info->len, obj_file) != info->len) {
		err = -EFAULT;
		goto out;
	}

out:
	if (err)
		free(info->hdr);

	return err;
}

static void free_copy(struct load_info *info)
{
	free(info->hdr);
}

static __unused int
create_mmap_vma_file(struct task *task, struct load_info *info)
{
	int ret = 0;
	ssize_t map_len = info->len;
	unsigned long __unused map_v;
	int __unused map_fd;
	char buffer1[BUFFER_SIZE];
	char buffer[BUFFER_SIZE];
	const char *filename;

	if (!(task->fto_flag & FTO_PROC)) {
		lerror("Need FTO_PROC task flag.\n");
		return -1;
	}

	filename = fmktempname(buffer1, BUFFER_SIZE,
		PATCH_VMA_TEMP_PREFIX "XXXXXX");
	if (!filename) {
		return -1;
	}

	/* Create ROOT_DIR/PID/TASK_PROC_MAP_FILES/filename */
	snprintf(buffer, BUFFER_SIZE - 1,
		ROOT_DIR "/%d/" TASK_PROC_MAP_FILES "%s", task->pid, filename);

	/* attach target task */
	task_attach(task->pid);

	map_fd = task_open(task, (char *)filename,
				O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (map_fd <= 0) {
		lerror("remote open failed.\n");
		return -1;
	}

	ret = task_ftruncate(task, map_fd, map_len);
	if (ret != 0) {
		lerror("remote ftruncate failed.\n");
		goto close_ret;
	}

	map_v = task_mmap(task,
				0UL, map_len,
				PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_PRIVATE, map_fd, 0);
	if (!map_v) {
		lerror("remote mmap failed.\n");
		goto close_ret;
	}

	task_detach(task->pid);

	update_task_vmas(task);

close_ret:
	task_close(task, map_fd);

	return ret;
}

static unsigned int find_sec(const struct load_info *info, const char *name)
{
	unsigned int i;

	for (i = 0; i < info->hdr->e_shnum; i++) {
		GElf_Shdr *shdr = &info->sechdrs[i];

		/* Alloc bit cleared means "ignore it." */
		if ((shdr->sh_flags & SHF_ALLOC)
			&& strcmp(info->secstrings + shdr->sh_name, name) == 0)
			return i;
	}
	return 0;
}

static __unused int setup_load_info(struct load_info *info)
{
	unsigned int i;

	info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;

	info->secstrings = (void *)info->hdr
		+ info->sechdrs[info->hdr->e_shstrndx].sh_offset;

	info->index.info = find_sec(info, SEC_UPATCH_INFO);
	// MORE info

	for (i = 1; i < info->hdr->e_shnum; i++) {

		if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
			info->index.sym = i;

			info->index.str = info->sechdrs[i].sh_link;

			info->strtab = (char *)info->hdr
				+ info->sechdrs[info->index.str].sh_offset;

			break;
		}
	}

	if (info->index.sym == 0) {
		lwarning("patch has no symbols (stripped).\n");
		return -ENOEXEC;
	}

	if (!info->name)
		info->name = "Name me";

	return 0;
}

static int rewrite_section_headers(struct load_info *info)
{
	unsigned int __unused i;

	// TODO:

	return 0;
}

static int load_patch(struct load_info *info)
{
	long err = 0;

	/* check ELF header */
	if (!check_ehdr_magic_is_ok(info->hdr)) {
		lerror("Invalid ELF header.\n");
		goto free_copy;
	}
	if (info->hdr->e_shoff >= info->len
		|| (info->hdr->e_shnum * sizeof(GElf_Shdr) >
			info->len - info->hdr->e_shoff)) {
		lerror("Bad section header.\n");
		goto free_copy;
	}

	err = setup_load_info(info);
	if (err)
		goto free_copy;

	err = rewrite_section_headers(info);
	if (err)
		goto free_copy;


free_copy:
	free_copy(info);
	return err;
}

// looks like init_module() in kernel
int init_patch(struct task *task, const char *obj_file)
{
	int err;
	struct load_info info = {};

	err = parse_load_info(obj_file, &info);
	if (err)
		return err;

	/**
	 * Create and mmap a temp file into target task, this temp file is under
	 * ROOT_DIR/PID/TASK_PROC_MAP_FILES directory, it's named by mktemp().
	 */
	err = create_mmap_vma_file(task, &info);
	if (err) {
		free_copy(&info);
		return err;
	}

	return load_patch(&info);
}

/* delete last patched patch, so, don't need any other arguments
 */
int delete_patch(struct task *task)
{
	// TODO:

	return 0;
}

