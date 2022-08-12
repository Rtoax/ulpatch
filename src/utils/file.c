// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>

#include <gelf.h>

#include <elf/elf_api.h>

#include "log.h"
#include "task.h"
#include "util.h"

int fsize(const char *filepath)
{
	int ret, fd;
	struct stat statbuf;

	fd = open(filepath, O_RDONLY);
	if (fd <= 0) {
		lerror("open %s failed.\n", filepath, strerror(errno));
		return -1;
	}
	ret = fstat(fd, &statbuf);
	if (ret != 0) {
		lerror("fstat %s failed.\n", filepath, strerror(errno));
		return -1;
	}
	return statbuf.st_size;
}

bool fexist(const char *filepath)
{
	return access(filepath, F_OK) == 0? true:false;
}

static int _file_type_mem(struct mmap_struct *mem)
{
	file_type type = FILE_UNKNOWN;
	GElf_Ehdr *ehdr = mem->mem;

	if (check_ehdr_magic_is_ok(ehdr)) {
		type = FILE_ELF;
		if (ehdr->e_type == ET_REL)
			type |= FILE_ELF_RELO;
	}

	return type;
}

static int _file_type(const char *filepath)
{
	file_type type = FILE_UNKNOWN;

	struct mmap_struct *f = fmmap_rdonly(filepath);
	if (!f)
		return FILE_UNKNOWN;

	type = _file_type_mem(f);

	fmunmap(f);

	return type;
}

file_type ftype(const char *filepath)
{
	return _file_type(filepath);
}

/* Make sure @srcpath is exist and @dstpath is not exist
 *
 * return - bytes of copy if success, -errno if fail
 */
static int _file_copy(const char *srcpath, const char *dstpath)
{
	FILE *in, *out;
	int nbytes = 0;

	in = fopen(srcpath, "r");
	if (!in) {
		lerror("open %s failed.\n", srcpath);
		return -errno;
	}
	out = fopen(dstpath, "w");
	if (!out) {
		lerror("open %s failed.\n", dstpath);
		fclose(in);
		return -errno;
	}

	while (1) {
		uint8_t c;

		fread(&c, 1, 1, in);
		if (feof(in))
			break;

		fwrite(&c, 1, 1, out);

		nbytes++;
	}

	fclose(in);
	fclose(out);

	ldebug("copy a %d bytes file.\n", nbytes);

	return nbytes;
}

int fcopy(const char *srcpath, const char *dstpath)
{
	int err, ret = 0;

	if (!srcpath || !dstpath) {
		lerror("NULL pointer.\n");
		return -EINVAL;
	}
	if (!fexist(srcpath) || fexist(dstpath)) {
		lerror("src not exist or dst exist\n");
		return -EEXIST;
	}

	err = _file_copy(srcpath, dstpath);
	if (err <= 0) {
		lerror("copy from %s to %s failed\n", srcpath, dstpath);
		ret = err;
	}

	return ret;
}

char* fmktempname(char *buf, int buf_len, char *seed)
{
	int fd;
	char *_seed = seed?:"/tmp/temp-XXXXXXX";

	snprintf(buf, buf_len, _seed);

	fd = mkstemp(buf);
	if (fd <= 0) {
		fprintf(stderr, "mkstemp: %s\n", strerror(errno));
		return NULL;
	}
	close(fd);
	unlink(buf);

	return basename(buf);
}

/* Load a @file to @mem, make sure @file exist in file system
 */
int copy_chunked_from_file(void *mem, int mem_len, const char *file)
{
	FILE *fp;
	int size = MIN(mem_len, fsize(file));

	fp = fopen(file, "r");

	fread(mem, size, 1, fp);

	fclose(fp);

	return size;
}

static struct mmap_struct *_mmap_file(const char *filepath, int flags, int prot)
{
	struct mmap_struct *mem = NULL;

	if (!fexist(filepath)) {
		lerror("%s not exist.\n", filepath);
		return NULL;
	}

	mem = malloc(sizeof(struct mmap_struct));
	assert(mem && "malloc fatal.");

	mem->filepath = strdup(filepath);
	mem->flags = flags;
	mem->prot = prot;

	mem->fd = open(filepath, flags);
	if (mem->fd <= 0) {
		lerror("open %s failed, %s\n", filepath, strerror(errno));
		goto free_mem;
	}

	mem->size = fsize(filepath);
	mem->mem = mmap(NULL, mem->size, prot, MAP_PRIVATE, mem->fd, 0);
	if (mem->mem == MAP_FAILED) {
		lerror("mmap %s failed, %s\n", filepath, strerror(errno));
		goto free_mem;
	}

	mem->ftype = _file_type_mem(mem);

	return mem;

free_mem:
	free(mem);
	return NULL;
}

static int _munmap_file(struct mmap_struct *mem)
{
	munmap(mem->mem, mem->size);
	close(mem->fd);
	free(mem->filepath);
	free(mem);
	return 0;
}

struct mmap_struct *fmmap_rdonly(const char *filepath)
{
	return _mmap_file(filepath, O_RDONLY, PROT_READ);
}

int fmunmap(struct mmap_struct *mem)
{
	return _munmap_file(mem);
}

