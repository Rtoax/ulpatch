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

