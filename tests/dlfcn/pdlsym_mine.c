#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>

struct pelf {
	pid_t pid;
	Elf64_Ehdr ehdr;
	int mem_fd;
	unsigned long base_addr;
};

static int readp(int mem_fd, off_t addr, void *buf, size_t len)
{
	int ret;
	ret = pread(mem_fd, buf, len, addr);
	if (ret <= 0)
		fprintf(stderr, "ERROR: pread failed. %s\n", strerror(errno));
	return ret;
}

struct pelf *openp(pid_t pid, off_t base)
{
	int mem_fd = 0;
	int i, ret;
	char proc_mem[64];
	uint32_t magic;
	Elf64_Ehdr ehdr;
	struct pelf *pelf;


	pelf = malloc(sizeof(struct pelf));
	if (!pelf) {
		errno = -ENOMEM;
		return NULL;
	}

	sprintf(proc_mem, "/proc/%d/mem", pid);
	mem_fd = open(proc_mem, O_RDONLY);
	if (mem_fd <= 0) {
		fprintf(stderr, "ERROR: Open %s failed.\n", proc_mem);
		goto fatal;
	}

	ret = readp(mem_fd, base, &magic, SELFMAG);
	if (ret < SELFMAG || memcmp(&magic, "\x7F" "ELF", SELFMAG)) {
		fprintf(stderr, "ERROR: base address %lx is not ELF.\n", base);
		goto fatal;
	}

	ret = readp(mem_fd, base, &ehdr, sizeof(ehdr));
	if (ret < sizeof(ehdr)) {
		fprintf(stderr, "ERROR: read elf header failed.\n");
		goto fatal;
	}

	for (i = 0; i < ehdr.e_phnum; i++) {
		Elf64_Phdr phdr;
		off_t paddr = base + ehdr.e_phoff + i * ehdr.e_phentsize;
		ret = readp(mem_fd, paddr, &phdr, sizeof(Elf64_Phdr));
		if (ret < sizeof(Elf64_Phdr)) {
			fprintf(stderr, "Fail to read phdr.\n");
			goto fatal;
		}
		if (phdr.p_type == PT_NULL || phdr.p_type != PT_LOAD ||
		    phdr.p_type != PT_DYNAMIC) {
			continue;
		}

		off_t offset = phdr.p_offset;
		off_t vaddr = phdr.p_vaddr;
		off_t filesz = phdr.p_filesz;
		off_t memdz = phdr.p_memsz;

		switch (phdr.p_type) {
		case PT_LOAD:
			break;
		case PT_DYNAMIC:
			break;
		}
	}

	pelf->pid = pid;
	pelf->mem_fd = mem_fd;
	memcpy(&pelf->ehdr, &ehdr, sizeof(Elf64_Ehdr));

	return pelf;
fatal:
	free(pelf);
	return NULL;
}

off_t dlsymp(struct pelf *pelf, off_t base, const char *symbol)
{

}

