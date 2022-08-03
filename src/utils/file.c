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

#include <gelf.h>

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
	GElf_Ehdr *ehdr = mem->mem;

	if (ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
		ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
		ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
		ehdr->e_ident[EI_MAG3] == ELFMAG3) {
		return FILE_ELF;
	}

	return FILE_UNKNOWN;
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


static struct mmap_struct *_mmap_file(const char *filepath, int flags, int prot)
{
	struct mmap_struct *mem = malloc(sizeof(struct mmap_struct));
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

