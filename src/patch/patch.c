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
#include <utils/patch.h>
#include <utils/list.h>
#include <utils/task.h>
#include <utils/compiler.h>

#include "patch.h"


// see linux:kernel/module.c
static int parse_load_info(struct task *task, const char *obj_file,
	struct load_info *info)
{
	int err = 0;
	char buffer1[BUFFER_SIZE];
	char buffer[BUFFER_SIZE];
	const char *filename;

	if (!fexist(obj_file)) {
		return -EEXIST;
	}

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
		ROOT_DIR "/%d/" TASK_PROC_MAP_FILES "/%s", task->pid, filename);

	info->patch_path = strdup(buffer);

	info->len = fsize(obj_file);
	if (info->len < sizeof(*(info->hdr))) {
		lerror("%s truncated.\n", obj_file);
		err = -ENOEXEC;
		goto out;
	}

	lwarning("mmap shmem: %s %d\n", info->patch_path, info->len);

	info->patch_mmap = fmmap_shmem_create(info->patch_path, info->len);
	if (!info->patch_mmap) {
		lerror("%s: fmmap failed.\n", info->patch_path);
		err = -1;
		goto out;
	}

	/* copy from file */
	if (copy_chunked_from_file(info->patch_mmap->mem, info->len,
			obj_file) != info->len) {
		lerror("copy chunk failed.\n");
		err = -EFAULT;
		goto out;
	}

	info->hdr = info->patch_mmap->mem;
	info->target_task = task;

out:

	return err;
}

static void free_copy(struct load_info *info)
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

static __unused int
create_mmap_vma_file(struct task *task, struct load_info *info)
{
	int ret = 0;
	ssize_t map_len = info->len;
	unsigned long __unused map_v;
	int __unused map_fd;

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
	info->target_addr = map_v;

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

			ldebug("found symtab %d\n", info->index.sym);

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
	unsigned int __unused i;

	/* This should always be true, but let's be sure. */
	info->sechdrs[0].sh_addr = 0;

	for (i = 1; i < info->hdr->e_shnum; i++) {
		GElf_Shdr *shdr = &info->sechdrs[i];

		if (shdr->sh_type != SHT_NOBITS
			&& info->len < shdr->sh_offset + shdr->sh_size) {
			lerror("Patch len %lu truncated\n", info->len);
			return -ENOEXEC;
		}

		/* Update sh_addr to point to target task address space. */
		shdr->sh_addr = (size_t)info->target_addr + shdr->sh_offset;
	}

	info->sechdrs[info->index.info].sh_flags &= ~(unsigned long)SHF_ALLOC;
	// MORE sechdrs

	return 0;
}

#ifndef ARCH_SHF_SMALL
#define ARCH_SHF_SMALL 0
#endif
#ifndef SHF_RO_AFTER_INIT
#define SHF_RO_AFTER_INIT	0x00200000
#endif

static void layout_sections(struct load_info *info)
{
	static __unused unsigned long const masks[][2] = {
		/* NOTE: all executable code must be the first section
		 * in this array; otherwise modify the text_size
		 * finder in the two loops below */
		{ SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
		{ SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
		{ SHF_RO_AFTER_INIT | SHF_ALLOC, ARCH_SHF_SMALL },
		{ SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
		{ ARCH_SHF_SMALL | SHF_ALLOC, 0 }
	};

	// TODO: i don't know what happen here
}

static void layout_symtab(struct load_info *info)
{
	GElf_Shdr __unused *symsect = info->sechdrs + info->index.sym;
	GElf_Shdr __unused *strsect = info->sechdrs + info->index.str;

	const GElf_Sym __unused *src;
	unsigned int __unused i, nsrc, ndst, strtab_size = 0;

	symsect->sh_flags |= SHF_ALLOC;
	//symsect->sh_entsize = get_offset()

	ldebug("\t%s\n", info->secstrings + symsect->sh_name);

	src = (void *)info->hdr + symsect->sh_offset;
	nsrc = symsect->sh_size / sizeof(*src);

	/* Compute total space required for the core symbols' strtab. */
	for (ndst = i = 0; i < nsrc; i++) {
	}

	// TODO: not consider symtab yet
}

static __unused int move_module(struct load_info *info)
{
	int i;
	void __unused *ptr = info->hdr;

	ldebug("final section addresses:\n");

	for (i = 0; i < info->hdr->e_shnum; i++) {
		void __unused *dest;
		GElf_Shdr *shdr = &info->sechdrs[i];

		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;

		/* Update sh_addr to point to target task address space.
		 * already do in rewrite_section_headers(),
		 */
		// shdr->sh_addr += (unsigned long)info->target_addr;

		ldebug("\t0x%lx %s\n",
			(long)shdr->sh_addr, info->secstrings + shdr->sh_name);
	}

	return 0;
}

static int layout_and_allocate(struct load_info *info)
{
	unsigned int __unused ndx;
	int __unused err;


	/* Determine total sizes, and put offsets in sh_entsize.  For now
	   this is done generically; there doesn't appear to be any
	   special cases for the architectures. */
	layout_sections(info);

	layout_symtab(info);

	err = move_module(info);
	if (err)
		return err;

	// MORE: memleak and mod relate

	return 0;
}

static int find_module_sections(struct load_info *info)
{
	// TODO:
	return 0;
}

static void setup_modinfo(struct load_info *info)
{
}

/* try find symbol in current patch, otherwise, search in libc and target task
 * symtab.
 */
static const struct symbol *resolve_symbol(const struct load_info *info,
			const char *name)
{
	const struct symbol *sym = NULL;
	const struct task *task = info->target_task;

	if (!task)
		return NULL;

	/* try find symbol in libc.so */
	if (task->fto_flag & FTO_LIBC) {
		sym = find_symbol(task->libc_elf, name);
	}
	/* try find symbol in SELF */
	if (task->fto_flag & FTO_SELF) {
		sym = find_symbol(task->exe_elf, name);
	}

	if (!sym) {
		lerror("Not find symbol in libc and %s\n", task->exe);
	}

	return sym;
}

static const struct symbol *
resolve_symbol_wait(const struct load_info *info, const char *name)
{
	const struct symbol *symbol;

	symbol = resolve_symbol(info, name);

	return symbol;
}

static int simplify_symbols(const struct load_info *info)
{
	GElf_Shdr *symsec = &info->sechdrs[info->index.sym];

	/* need relocate sh_addr, because here is HOST task, not target task */
	GElf_Sym *sym = (void *)info->hdr + symsec->sh_addr - info->target_addr;

	ldebug("sym = %lp + %lx - %lx, sh_offset %lx\n",
		info->hdr, symsec->sh_addr, info->target_addr, symsec->sh_offset);

	unsigned long __unused secbase;
	unsigned int i;
	int __unused ret = 0;
	const struct symbol __unused *symbol;


	for (i = 1; i < symsec->sh_size / sizeof(GElf_Sym); i++) {
		const char *name = info->strtab + sym[i].st_name;

		switch (sym[i].st_shndx) {

		case SHN_COMMON:
			ldebug("Common symbol: %s\n", name);
			lwarning("please compile with -fno-common.\n");
			ret = -ENOEXEC;
			break;

		case SHN_ABS:
			ldebug("Absolute symbol: 0x%08lx\n",
				(long)sym[i].st_value);
			break;

		case SHN_UNDEF:
			ldebug("Solve UNDEF sym %s\n", name);
			symbol = resolve_symbol_wait(info, name);
			if (symbol) {
				sym[i].st_value = symbol->sym.st_value;
			}

			/* Ok if weak.  */
			if (!symbol && GELF_ST_BIND(sym[i].st_info) == STB_WEAK) {
				break;
			}

			/* Not found symbol in any where */
			ret = symbol ?0:-ENOENT;

			lwarning("Unknown symbol %s (err %d)\n", name, ret);

			break;

		default:
			ldebug("OK, the symbol in this patch. %s\n", name);

			secbase = info->sechdrs[sym[i].st_shndx].sh_addr;

			sym[i].st_value += secbase;
			break;
		}
	}

	return ret;
}

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
	/* need add_allsyms() ...
	 */

	// TODO:

	return 0;
}

static int kick_target_process(const struct load_info *info)
{
	ssize_t n;
	int err = 0;
	struct task *task = info->target_task;
	unsigned long target_addr = info->target_addr;

	/* copy patch to target address space
	 */
	n = memcpy_to_task(task, target_addr, info->hdr, info->len);
	if (n < info->len) {
		lerror("failed kick target process.\n");
		err = -ENOEXEC;
	}

	return err;
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

	err = layout_and_allocate(info);
	if (err)
		goto free_copy;

	err = find_module_sections(info);
	if (err)
		goto free_copy;

	setup_modinfo(info);

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
	free_copy(info);
	return err;
}

// looks like init_module() in kernel
int init_patch(struct task *task, const char *obj_file)
{
	int err;
	struct load_info info = {};

	err = parse_load_info(task, obj_file, &info);
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

