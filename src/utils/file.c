// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <dirent.h>

#include <gelf.h>

#include <elf/elf-api.h>

#include <utils/log.h>
#include <task/task.h>
#include <utils/util.h>


int fsize(const char *filepath)
{
	int ret, fd;
	struct stat statbuf;

	fd = open(filepath, O_RDONLY);
	if (fd <= 0) {
		ulp_error("open %s failed %s.\n", filepath, strerror(errno));
		return -1;
	}
	ret = fstat(fd, &statbuf);
	if (ret != 0) {
		ulp_error("fstat %s failed %s.\n", filepath, strerror(errno));
		return -1;
	}
	close(fd);

	return statbuf.st_size;
}

bool fexist(const char *filepath)
{
	if (!filepath) {
		errno = EINVAL;
		return false;
	}
	return access(filepath, F_OK) == 0 ? true : false;
}

int fremove(const char *filepath)
{
	int ret = 0;
	struct stat st;

	if (!filepath)
		return -1;
	if (!fexist(filepath))
		return 0;

	lstat(filepath, &st);

	if (S_ISDIR(st.st_mode))
		ret = rmdir(filepath);
	else
		ret = unlink(filepath);

	return ret;
}

int ftouch(const char *filepath)
{
	struct stat st;
	int fd;

	if (!filepath)
		return -1;

	lstat(filepath, &st);

	if (fexist(filepath) && S_ISREG(st.st_mode))
		return 0;
	else if (fexist(filepath))
		return -1;

	fd = open(filepath, O_WRONLY | O_EXCL | O_CREAT, 0644);
	if (fd <= 0) {
		ulp_debug("touch %s failed\n", filepath);
		return -errno;
	}
	close(fd);
	return 0;
}

static int __remove_recursive(const char *path)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat dir_stat;
	char dir_name[PATH_MAX];

	/* path not exist */
	if (!fexist(path)) {
		return 0;
	}

	/* get attribution error */
	if (stat(path, &dir_stat) == -1) {
		ulp_error("get dir:%s stat error.\n", path);
		return -1;
	}

	/* regular file, delete */
	if (S_ISREG(dir_stat.st_mode)) {
		ulp_debug("Delete file %s\n", path);
		remove(path);
	} else if (S_ISDIR(dir_stat.st_mode)) {
		dirp = opendir(path);
		while ((dp = readdir(dirp))!= NULL) {
			if ((0 == strcmp(".", dp->d_name)) ||
			    (0 == strcmp("..", dp->d_name)))
				continue;
			sprintf(dir_name, "%s/%s", path, dp->d_name);
			__remove_recursive(dir_name);
		}
		closedir(dirp);
		ulp_debug("Delete dir %s\n", path);
		rmdir(path);
	} else {
		ulp_error("unknow type: %s!\n", path);
	}
	return 0;
}

int fremove_recursive(const char *filepath)
{
	return __remove_recursive(filepath);
}

static int _file_type_mem(struct mmap_struct *mem)
{
	file_type type = FILE_UNKNOWN;
	GElf_Ehdr *ehdr = mem->mem;

	if (ehdr_magic_ok(ehdr)) {
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
	int n, nbytes = 0;

	in = fopen(srcpath, "r");
	if (!in) {
		ulp_error("open %s failed.\n", srcpath);
		return -errno;
	}
	out = fopen(dstpath, "w");
	if (!out) {
		ulp_error("open %s failed.\n", dstpath);
		fclose(in);
		return -errno;
	}

	while (1) {
		uint8_t c;

		n = fread(&c, 1, 1, in);
		if (n != 1 || feof(in))
			break;

		n = fwrite(&c, 1, 1, out);
		if (n != 1)
			break;

		nbytes++;
	}

	fclose(in);
	fclose(out);

	ulp_debug("copy a %d bytes file.\n", nbytes);

	return nbytes;
}

int fcopy(const char *srcpath, const char *dstpath)
{
	int err, ret = 0;

	if (!srcpath || !dstpath) {
		ulp_error("NULL pointer.\n");
		return -EINVAL;
	}
	if (!fexist(srcpath) || fexist(dstpath)) {
		ulp_error("src not exist or dst exist\n");
		return -EEXIST;
	}

	err = _file_copy(srcpath, dstpath);
	if (err <= 0) {
		ulp_error("copy from %s to %s failed\n", srcpath, dstpath);
		ret = err;
	}

	return ret;
}

char* fmktempfile(char *buf, int buf_len, char *seed)
{
	int fd;
	const char *_seed = seed ?: "/tmp/temp-XXXXXX";

	snprintf(buf, buf_len, "%s", _seed);

	fd = mkstemp(buf);
	if (fd <= 0) {
		fprintf(stderr, "mkstemp: %s\n", strerror(errno));
		return NULL;
	}
	close(fd);

	return buf;
}

char* fmktempname(char *buf, int buf_len, char *seed)
{
	char *file = fmktempfile(buf, buf_len, seed);
	unlink(file);
	return basename(buf);
}

/* Load a @file to @mem, make sure @file exist in file system */
int fmemcpy(void *mem, int mem_len, const char *file)
{
	FILE *fp;
	int n, size = MIN(mem_len, fsize(file));

	fp = fopen(file, "r");
	n = fread(mem, size, 1, fp);
	if (n != 1) {
		ulp_error("fread: %m\n");
		return 0;
	}
	fclose(fp);

	return size;
}

static struct mmap_struct *_mmap_file(const char *filepath, int o_flags,
				      int m_flags, int prot,
				      size_t truncate_size)
{
	int ret;
	struct mmap_struct *mem = NULL;

	if (!(o_flags & O_CREAT) && !fexist(filepath)) {
		ulp_error("%s not exist.\n", filepath);
		return NULL;
	}

	mem = malloc(sizeof(struct mmap_struct));
	if (!mem) {
		ulp_error("Malloc mmap_struct failed.\n");
		exit(1);
	}

	mem->filepath = strdup(filepath);
	mem->open_flags = o_flags;
	mem->mmap_flags = m_flags;
	mem->prot = prot;

	mem->fd = open(filepath, o_flags, 0644);
	if (mem->fd <= 0) {
		ulp_error("open %s failed, %s\n", filepath, strerror(errno));
		goto free_mem;
	}

	if (truncate_size) {
		ret = ftruncate(mem->fd, truncate_size);
		if (ret != 0) {
			fprintf(stderr, "ftruncate: %s\n", strerror(errno));
			return NULL;
		}
	}

	mem->size = truncate_size ?: fsize(filepath);
	mem->mem = mmap(NULL, mem->size, prot, m_flags, mem->fd, 0);
	if (mem->mem == MAP_FAILED) {
		ulp_error("mmap %s failed, %s\n", filepath, strerror(errno));
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
	return _mmap_file(filepath, O_RDONLY, MAP_PRIVATE, PROT_READ, 0);
}

struct mmap_struct *fmmap_shmem_create(const char *filepath, size_t size)
{
	/* @PROT_EXEC cause i need it */
	return _mmap_file(filepath, O_RDWR | O_CREAT | O_TRUNC, MAP_SHARED,
			PROT_READ | PROT_WRITE | PROT_EXEC, size);
}

int fmunmap(struct mmap_struct *mem)
{
	return _munmap_file(mem);
}

int fprint_file(FILE *out, const char *file)
{
	int ret = 0;
	char str[32] = {0};
	FILE *fp = fopen(file, "r");

	if (!fp)
		return -1;

	while (fgets(str, sizeof(str), fp))
		ret += fprintf(out, "%s", str);

	fclose(fp);
	return ret;
}

int fprint_fd(FILE *fp, int fd)
{
	char ch;
	int cnt = 0;

	if (fp == NULL)
		fp = stdout;

	lseek(fd, 0, SEEK_SET);

	while (read(fd, &ch, 1) == 1) {
		fputc(ch, fp);
		cnt++;
	}
	return cnt;
}

