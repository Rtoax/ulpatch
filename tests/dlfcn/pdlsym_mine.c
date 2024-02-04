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
	unsigned long base;
	off_t strtab, symtab, strsz, syment;
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
	off_t strtab, symtab, strsz, syment;

	pelf = malloc(sizeof(struct pelf));
	if (!pelf) {
		errno = -ENOMEM;
		return NULL;
	}

	strtab = symtab = strsz = syment = 0;

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

		if (phdr.p_type == PT_NULL && phdr.p_type != PT_LOAD &&
		    phdr.p_type != PT_DYNAMIC) {
			continue;
		}

		fprintf(stderr, "handle a program header %d\n", phdr.p_type);

		off_t offset = phdr.p_offset;
		off_t vaddr = phdr.p_vaddr;
		off_t filesz = phdr.p_filesz;
		off_t memsz = phdr.p_memsz;

		if (phdr.p_type == PT_LOAD) {
			if (ehdr.e_type == ET_EXEC) {
				if (vaddr - offset < base) {
					errno = -EFAULT;
					goto fatal;
				}
			}
		} else if (phdr.p_type == PT_DYNAMIC) {
			int id;
			Elf64_Dyn dyn;
			off_t tag = (ehdr.e_type == ET_EXEC ? 0 : base) + vaddr;
			fprintf(stderr, "tag = %lx\n", tag);
			for (id = 0; id * sizeof(Elf64_Dyn) < memsz; id++) {
				ret = readp(mem_fd,
					    tag + id * sizeof(Elf64_Dyn),
					    &dyn,
					    sizeof(Elf64_Dyn));
				if (ret < sizeof(Elf64_Dyn)) {
					fprintf(stderr, "Failed read dyn.\n");
					goto fatal;
				}
				switch (dyn.d_tag) {
				case DT_STRTAB:
					fprintf(stderr, "DT_STRTAB\n");
					strtab = dyn.d_un.d_val;
					break;
				case DT_SYMTAB:
					fprintf(stderr, "DT_SYMTAB\n");
					symtab = dyn.d_un.d_val;
					break;
				case DT_STRSZ:
					fprintf(stderr, "DT_STRSZ\n");
					strsz = dyn.d_un.d_val;
					break;
				case DT_SYMENT:
					fprintf(stderr, "DT_SYMENT\n");
					syment = dyn.d_un.d_val;
					break;
				}
			}
		}
	}

	/* Check that we have all program headers required for dynamic linking */
	if (!strtab || !symtab || !strsz || !syment) {
		fprintf(stderr, "No found DT_\n");
		goto fatal;
	}

	/* String table (immediately) follows the symbol table */
	if (symtab >= strtab) {
		fprintf(stderr, "symtab >= strtab\n");
		goto fatal;
	}

	/* Symbol entry size is a non-zero integer that divides symtab size */
	if ((strtab - symtab) % syment) {
		fprintf(stderr, "(strtab - symtab) %% syment != 0\n");
		goto fatal;
	}

	pelf->pid = pid;
	pelf->mem_fd = mem_fd;
	pelf->base = base;
	memcpy(&pelf->ehdr, &ehdr, sizeof(Elf64_Ehdr));
	pelf->strtab = strtab;
	pelf->symtab = symtab;
	pelf->strsz = strsz;
	pelf->syment = syment;

	return pelf;
fatal:
	free(pelf);
	if (mem_fd)
		close(mem_fd);
	return NULL;
}

static int symiter(struct pelf *pelf, int i, uint32_t *stridx, uintptr_t *value)
{
	int ret;
	Elf64_Sym sym;
	off_t sym_addr = pelf->symtab + i * pelf->syment;

	if (i * pelf->syment >= pelf->strtab - pelf->symtab) {
		fprintf(stderr, "Out of bound.\n");
		return 0;
	}

	if (pelf->symtab < pelf->base)
		sym_addr += pelf->base;

	ret = readp(pelf->mem_fd, sym_addr, &sym, sizeof(Elf64_Sym));
	if (ret < sizeof(Elf64_Sym)) {
		fprintf(stderr, "Read sym failed.\n");
		return 0;
	}

	*stridx = sym.st_name;

	if (*stridx < pelf->strsz && pelf->ehdr.e_type != ET_EXEC) {
		*value = sym.st_value + pelf->base;
		fprintf(stderr, "value = %lx\n", *value);
		return 1;
	}

	fprintf(stderr, "End of sym iter. %ld, %ld\n",
		sym.st_name, pelf->strsz);
	return 0;
}

off_t dlsymp(struct pelf *pelf, const char *symbol)
{
	int i, ret;
	uint32_t stridx;
	off_t strtab;
	uintptr_t value = 0;
	size_t size = strlen(symbol) + 1;

	//strtab = pelf->strtab + (pelf->strtab < pelf->base) ? pelf->base : 0;
	strtab = pelf->strtab;
	for (i = 0; symiter(pelf, i, &stridx, &value); value = 0, i++) {
		if (value && stridx + size <= pelf->strsz) {
			char buf[512];
			/**
			 * TODO: Only read some specified length.
			 */
			ret = readp(pelf->mem_fd, strtab + stridx, buf, size);
			if (ret < size) {
				fprintf(stderr, "Failed read symbol.\n");
				continue;
			}
			fprintf(stderr, "sym: %s : %lx\n", buf, value);
		}
	}
	return (off_t)value;
}

