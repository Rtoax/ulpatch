// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 Rong Tao <rtoax@foxmail.com> */
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

#include <patch/patch.h>


/* free load_info */
static void free_info(struct load_info *info)
{
	if (info->patch_mmap) {
		fmunmap(info->patch_mmap);
		info->patch_mmap = NULL;
	}

	if (info->patch_path) {
		free(info->patch_path);
		info->patch_path = NULL;
	}
}

/* Upatch is single thread, thus, this api is ok. */
static char* make_pid_objname_unsafe(pid_t pid)
{
	static char name[BUFFER_SIZE];
	char buffer1[BUFFER_SIZE];
	const char *s;
	int ret;

make:
	/* make patch-XXXXXX temp file name */
	s = fmktempname(buffer1, BUFFER_SIZE, PATCH_VMA_TEMP_PREFIX "XXXXXX");
	if (!s)
		goto make;

	/* Create ROOT_DIR/PID/TASK_PROC_MAP_FILES/obj_file, seems like:
	 * /tmp/upatch/5465/map_files/patch-AbIRYY */
	ret = snprintf(name, BUFFER_SIZE - 1,
		ROOT_DIR "/%d/" TASK_PROC_MAP_FILES "/%s", pid, s);
	if (ret <= 0)
		/* try again */
		goto make;

	return name;
}

/* see linux:kernel/module.c */
int parse_load_info(const char *obj_from, const char *obj_to,
	struct load_info *info)
{
	int err = 0;

	/* source object file must exist. */
	if (!fexist(obj_from)) {
		lerror("%s not exist, command 'make install' is needed.\n", obj_from);
		return -EEXIST;
	}

	info->patch_path = strdup(obj_to);

	info->len = fsize(obj_from);
	if (info->len < sizeof(*(info->hdr))) {
		lerror("%s truncated.\n", obj_from);
		err = -ENOEXEC;
		goto out;
	}

	/* allocate memory for object file */
	info->patch_mmap = fmmap_shmem_create(info->patch_path, info->len);
	if (!info->patch_mmap) {
		lerror("%s: fmmap failed.\n", info->patch_path);
		err = -1;
		goto out;
	}

	/* copy from file */
	if (copy_chunked_from_file(info->patch_mmap->mem, info->len,
			obj_from) != info->len) {
		lerror("copy chunk failed.\n");
		err = -EFAULT;
		goto out;
	}

	/* This is the header of brand new object ELF file. */
	info->hdr = info->patch_mmap->mem;

	if (!ehdr_magic_ok(info->hdr)) {
		lerror("Invalid ELF format: %s\n", obj_from);
		err = -1;
		goto free_out;
	}
	if (info->hdr->e_shoff >= info->len
		|| (info->hdr->e_shnum * sizeof(GElf_Shdr) >
			info->len - info->hdr->e_shoff)) {
		lerror("Bad section header.\n");
		goto free_out;
	}

out:
	return err;

free_out:
	free_info(info);
	return err;
}

static int
create_mmap_vma_file(struct task *task, struct load_info *info)
{
	int ret = 0;
	ssize_t map_len = info->len;
	unsigned long map_v;
	int map_fd;

	/* attach target task */
	task_attach(task->pid);

	map_fd = task_open(task, (char *)info->patch_path,
				O_RDWR, 0644);
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
				MAP_SHARED, map_fd, 0);
	if (!map_v) {
		lerror("remote mmap failed.\n");
		goto close_ret;
	}

	/* save the address */
	info->target_hdr = map_v;

	update_task_vmas(task);

	ldebug("Done to create patch vma, addr 0x%lx\n", map_v);

close_ret:
	task_close(task, map_fd);

	task_detach(task->pid);

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

static int parse_upatch_strtab(struct upatch_strtab *s, const char *strtab)
{
	const char *p = strtab;

	s->magic = p;

	if (strcmp(s->magic, SEC_UPATCH_MAGIC)) {
		return -ENOENT;
	}

	while (*(p++));
	s->patch_type = p;

	while (*(p++));
	s->src_func = p;

	while (*(p++));
	s->dst_func = p;

	while (*(p++));
	s->author = p;

	ldebug("%s %s %s %s %s\n",
		s->magic, s->patch_type, s->src_func, s->dst_func, s->author);

	return 0;
}

/**
 * Set up our basic convenience variables (pointers to section headers,
 * search for module section index etc), and do some basic section
 * verification.
 */
int setup_load_info(struct load_info *info)
{
	unsigned int i;
	int err = 0;

	info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;

	info->secstrings = (void *)info->hdr
		+ info->sechdrs[info->hdr->e_shstrndx].sh_offset;

	/* found ".upatch.info" */
	info->index.info = find_sec(info, SEC_UPATCH_INFO);
	if (info->index.info == 0) {
		lerror("Not found %s section.\n", SEC_UPATCH_INFO);
		return -EEXIST;
	}

	info->info = (void *)info->hdr
		+ info->sechdrs[info->index.info].sh_offset;

	/* see UPATCH_INFO macro */
	ldebug("UPATCH INFO: pad: %u %u %u %u\n",
		info->info->pad[0], info->info->pad[1],
		info->info->pad[2], info->info->pad[3]);

	/* found ".upatch.strtab" */
	info->index.upatch_strtab = find_sec(info, SEC_UPATCH_STRTAB);
	const char *upatch_strtab = (void *)info->hdr
		+ info->sechdrs[info->index.upatch_strtab].sh_offset;

	memshowinlog(LOG_INFO, upatch_strtab, 64);

	err = parse_upatch_strtab(&info->upatch_strtab, upatch_strtab);
	if (err) {
		lerror("Failed parse upatch_strtab.\n");
		return -ENOENT;
	}

	/* Get patch type */
	if (!strcmp(info->upatch_strtab.patch_type, UPATCH_TYPE_PATCH_STR))
		info->type = UPATCH_TYPE_PATCH;
	else if (!strcmp(info->upatch_strtab.patch_type, UPATCH_TYPE_FTRACE_STR))
		info->type = UPATCH_TYPE_FTRACE;
	else {
		lerror("Unknown upatch type %s.\n", info->upatch_strtab.patch_type);
		return -ENOENT;
	}

	// TODO+MORE info

	/* Find internal symbols and strings. */
	for (i = 1; i < info->hdr->e_shnum; i++) {

		if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
			info->index.sym = i;

			info->index.str = info->sechdrs[i].sh_link;

			info->strtab = (char *)info->hdr
				+ info->sechdrs[info->index.str].sh_offset;

			ldebug("found symtab %d\n", info->index.sym);

			break;
		}
	}

	/* Object/Patch has no symbols (stripped?) */
	if (info->index.sym == 0) {
		lwarning("patch has no symbols (stripped).\n");
		return -ENOEXEC;
	}

	if (!info->name)
		info->name = "Name me";

	return 0;
}

/* Additional bytes needed by arch in front of individual sections */
unsigned int __weak arch_mod_section_prepend(unsigned int section)
{
	/* default implementation just returns zero */
	return 0;
}

/* Update size with this section: return offset. */
static long __unused get_offset(unsigned int *size, GElf_Shdr *sechdr,
		unsigned int section)
{
	long ret;

	*size += arch_mod_section_prepend(section);
	ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
	*size = ret + sechdr->sh_size;
	return ret;
}

static int rewrite_section_headers(struct load_info *info)
{
	unsigned int i;

	/* This should always be true, but let's be sure. */
	info->sechdrs[0].sh_addr = 0;

	for (i = 1; i < info->hdr->e_shnum; i++) {
		GElf_Shdr *shdr = &info->sechdrs[i];

		if (shdr->sh_type != SHT_NOBITS
			&& info->len < shdr->sh_offset + shdr->sh_size) {
			lerror("Patch len %lu truncated\n", info->len);
			return -ENOEXEC;
		}

		/**
		 * Update sh_addr to point to target task address space.
		 *
		 *  +---+
		 *  |   | <--- hdr(current task), target_hdr(target task)
		 *  |   |
		 *  |   |
		 *  |   |   shdr->sh_offset
		 *  |   |
		 *  |   |
		 *  |   | <--- shdr->sh_addr
		 *  |   |
		 *  +---+
		 */
		shdr->sh_addr = (size_t)info->target_hdr + shdr->sh_offset;
	}

	/* Track but don't keep info or other sections. */
	info->sechdrs[info->index.info].sh_flags &= ~(unsigned long)SHF_ALLOC;

	/* MORE: sechdrs */

	return 0;
}

#ifndef ARCH_SHF_SMALL
#define ARCH_SHF_SMALL 0
#endif
#ifndef SHF_RO_AFTER_INIT
#define SHF_RO_AFTER_INIT	0x00200000
#endif


/**
 * Try find symbol in current patch, otherwise, search in libc and target task
 * symtab.
 *
 * @return: 0-failed
 */
static const unsigned long
resolve_symbol(const struct load_info *info, const char *name)
{
	const struct symbol *sym = NULL;
	const struct task *task = info->target_task;
	unsigned long addr = 0;

	if (!task)
		return 0;

	/* try find symbol in SELF */
	if (task->fto_flag & FTO_SELF) {
		sym = find_symbol(task->exe_elf, name);
		if (sym) {
			addr = sym->sym.st_value;
			goto found;
		}
	}

	/* try find symbol address from @plt */
	if (task->fto_flag & FTO_SELF_PLT) {
		addr = objdump_elf_plt_symbol_address(task->objdump, name);
		if (addr)
			goto found;
	}

	/* try find symbol in libc.so */
	if (!sym && task->fto_flag & FTO_LIBC) {
		sym = find_symbol(task->libc_elf, name);
		if (sym) {
			addr = sym->sym.st_value;
			goto found;
		}
	}

	/* try find symbol in other libraries mapped in target process address
	 * space */
	if (!sym && task->fto_flag & FTO_VMA_ELF_SYMBOLS) {
		sym = task_vma_find_symbol((struct task *)task, name);
		if (sym) {
			addr = sym->sym.st_value;
			goto found;
		}
	}

	if (!sym) {
		lerror("Not find symbol in libc and %s\n", task->exe);
	}

found:
	return addr;
}

/* Change all symbols so that st_value encodes the pointer directly. */
static int simplify_symbols(const struct load_info *info)
{
	GElf_Shdr *symsec = &info->sechdrs[info->index.sym];

	/* need relocate sh_addr, because here is HOST task, not target task */
	GElf_Sym *sym = (void *)info->hdr + symsec->sh_addr - info->target_hdr;

	ldebug("sym = %lp + %lx - %lx, sh_offset %lx\n",
		info->hdr, symsec->sh_addr, info->target_hdr, symsec->sh_offset);

	unsigned long secbase;
	unsigned int i;
	int ret = 0;


	for (i = 1; i < symsec->sh_size / sizeof(GElf_Sym); i++) {
		const char *name = info->strtab + sym[i].st_name;

		switch (sym[i].st_shndx) {
		case SHN_COMMON:
			/* Ignore common symbols */
			if (!strncmp(name, "__gnu_lto", 9))
				break;
			ldebug("Common symbol: %s\n", name);
			lwarning("please compile with -fno-common.\n");
			ret = -ENOEXEC;
			break;

		case SHN_ABS:
			/* Don't need to do anything */
			ldebug("Absolute symbol: 0x%08lx\n", (long)sym[i].st_value);
			break;

		case SHN_UNDEF:
			ldebug("Resolve UNDEF sym %s\n", name);
			const unsigned long symbol_addr = resolve_symbol(info, name);
			/* Ok if resolved.  */
			if (symbol_addr) {
				sym[i].st_value = symbol_addr;
			}

			/* Ok if weak.  */
			if (!symbol_addr && GELF_ST_BIND(sym[i].st_info) == STB_WEAK) {
				break;
			}

			/* Not found symbol in any where */
			ret = symbol_addr ? 0 : -ENOENT;

			lwarning("Unknown symbol %s (err %d)\n", name, ret);

			break;

		default:
			ldebug("OK, the symbol in this patch. %s\n", name);

			/* The address in the target process */
			secbase = info->sechdrs[sym[i].st_shndx].sh_addr;

			sym[i].st_value += secbase;
			break;
		}
	}

	return ret;
}

/**
 * Relocation is the process of connecting symbolic references with symbolic
 * definitions.
 *
 * refs:
 * [0] https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/6n33n7fct/index.html
 */
static int apply_relocations(const struct load_info *info)
{
	unsigned int i;
	int err = 0;

	/* Now do relocations. */
	for (i = 0; i< info->hdr->e_shnum; i++) {
		unsigned int infosec = info->sechdrs[i].sh_info;

		/* Not a valid relocation section? */
		if (infosec >= info->hdr->e_shnum)
			continue;

		/* Don't bother with non-allocated sections */
		if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC))
			continue;

		if (unlikely(info->sechdrs[i].sh_type == SHT_REL)) {
			// Not support 32bit SHT_REL yet
			err = -ENOEXEC;
			break;
		} else if (info->sechdrs[i].sh_type == SHT_RELA) {

			err = apply_relocate_add(info, info->sechdrs, info->strtab,
						info->index.sym, i);
		}

		if (err < 0)
			break;
	}

	return err;
}

static int post_relocation(const struct load_info *info)
{
	/* TODO: need add_allsyms() */

	return 0;
}

static int kick_target_process(const struct load_info *info)
{
	ssize_t n;
	int err = 0;
	struct task *task = info->target_task;
	unsigned long target_hdr = info->target_hdr;

	/* copy patch to target address space */
	n = memcpy_to_task(task, target_hdr, info->hdr, info->len);
	if (n < info->len) {
		lerror("failed kick target process.\n");
		err = -ENOEXEC;
	}

	return err;
}

static int load_patch(struct load_info *info)
{
	long err = 0;

	err = setup_load_info(info);
	if (err)
		goto free_copy;

	/* TODO: Blacklists */
	/* TODO: Sign check */

	err = rewrite_section_headers(info);
	if (err)
		goto free_copy;

	/* Fix up syms, so that st_value is a pointer to location. */
	err = simplify_symbols(info);
	if (err < 0)
		goto free_copy;

	err = apply_relocations(info);
	if (err < 0)
		goto free_copy;

	err = post_relocation(info);
	if (err < 0)
		goto free_copy;

	err = kick_target_process(info);
	if (err < 0)
		goto free_copy;

	// TODO

free_copy:
	free_info(info);
	return err;
}

/* looks like init_module() in kernel */
int init_patch(struct task *task, const char *obj_file)
{
	int err;
	struct load_info info = {
		.target_task = task,
	};

	if (!(task->fto_flag & FTO_PROC)) {
		lerror("Need FTO_PROC task flag.\n");
		return -1;
	}

	const char *obj_to = make_pid_objname_unsafe(task->pid);

	err = parse_load_info(obj_file, obj_to, &info);
	if (err) {
		lerror("Parse %s failed.\n", obj_file);
		return err;
	}

	/**
	 * Create and mmap a temp file into target task, this temp file is under
	 * ROOT_DIR/PID/TASK_PROC_MAP_FILES directory, it's named by mktemp().
	 */
	err = create_mmap_vma_file(task, &info);
	if (err) {
		free_info(&info);
		return err;
	}

	return load_patch(&info);
}

/* delete last patched patch, so, don't need any other arguments */
int delete_patch(struct task *task)
{
	// TODO:

	return 0;
}

