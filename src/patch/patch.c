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

#ifndef SHF_RELA_LIVEPATCH
#define SHF_RELA_LIVEPATCH      0x00100000
#endif

/* free load_info */
void release_load_info(struct load_info *info)
{
	if (info->patch.mmap) {
		fmunmap(info->patch.mmap);
		info->patch.mmap = NULL;
	}

	if (info->patch.path) {
		free(info->patch.path);
		info->patch.path = NULL;
	}
}

/* ULPatch is single thread, thus, this api is ok. */
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
	 * /tmp/ulpatch/5465/map_files/patch-AbIRYY */
	ret = snprintf(name, BUFFER_SIZE - 1,
		ROOT_DIR "/%d/" TASK_PROC_MAP_FILES "/%s", pid, s);
	if (ret <= 0)
		/* try again */
		goto make;

	return name;
}

/* see linux:kernel/module.c */
int alloc_patch_file(const char *obj_from, const char *obj_to,
			struct load_info *info)
{
	int err = 0;

	/* source object file must exist. */
	if (!fexist(obj_from)) {
		lerror("%s not exist, command 'make install' is needed.\n", obj_from);
		return -EEXIST;
	}

	info->patch.path = strdup(obj_to);

	info->len = fsize(obj_from);
	if (info->len < sizeof(*(info->hdr))) {
		lerror("%s truncated.\n", obj_from);
		err = -ENOEXEC;
		goto out;
	}

	/* allocate memory for object file */
	info->patch.mmap = fmmap_shmem_create(info->patch.path, info->len);
	if (!info->patch.mmap) {
		lerror("%s: fmmap failed.\n", info->patch.path);
		err = -1;
		goto out;
	}

	/* copy from file */
	if (fmemcpy(info->patch.mmap->mem, info->len, obj_from) != info->len) {
		lerror("copy chunk failed.\n");
		err = -EFAULT;
		goto out;
	}

	/* This is the header of brand new object ELF file. */
	info->hdr = info->patch.mmap->mem;

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
	release_load_info(info);
	return err;
}

static int create_mmap_vma_file(struct task *task, struct load_info *info)
{
	int ret = 0;
	ssize_t map_len = info->len;
	unsigned long map_v, addr;
	int map_fd;
	int prot;

	/* attach target task */
	task_attach(task->pid);

	map_fd = task_open(task, (char *)info->patch.path, O_RDWR, 0644);
	if (map_fd <= 0) {
		lerror("remote open failed.\n");
		return -1;
	}

	ret = task_ftruncate(task, map_fd, map_len);
	if (ret != 0) {
		lerror("remote ftruncate failed.\n");
		ret = -EFAULT;
		goto close_ret;
	}

	addr = find_vma_span_area(task, map_len);
	if ((addr & 0x00000000FFFFFFFFUL) != addr) {
		lerror("Not found 4 bytes length span area in memory space.\n");
		ret = -EFAULT;
		goto close_ret;
	}

	prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	map_v = task_mmap(task, addr, map_len, prot, MAP_SHARED, map_fd, 0);
	if (!map_v) {
		lerror("remote mmap failed.\n");
		ret = -EFAULT;
		goto close_ret;
	}

	/* save the target mmap address */
	info->target_hdr = map_v;

	update_task_vmas(task);
	ldebug("Done to create patch vma, addr 0x%lx\n", map_v);

close_ret:
	task_close(task, map_fd);
	task_detach(task->pid);
	return ret;
}

static void delete_mmap_vma_file(struct task *task, struct load_info *info)
{
	task_attach(task->pid);
	task_munmap(task, info->target_hdr, info->len);
	update_task_vmas(task);
	task_detach(task->pid);
}

static unsigned int find_sec(const struct load_info *info, const char *name)
{
	unsigned int i;

	for (i = 0; i < info->hdr->e_shnum; i++) {
		GElf_Shdr *shdr = &info->sechdrs[i];

		/* Alloc bit cleared means "ignore it." */
		if (strcmp(info->secstrings + shdr->sh_name, name) == 0)
			return i;
	}
	return 0;
}

static int parse_ulpatch_strtab(struct ulpatch_strtab *s, const char *strtab)
{
	const char *p = strtab;

	s->magic = p;

	if (strcmp(s->magic, SEC_ULPATCH_MAGIC)) {
		lerror("No magic %s found.\n", SEC_ULPATCH_MAGIC);
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

	/* found ".ulpatch.info" */
	info->index.info = find_sec(info, SEC_ULPATCH_INFO);
	if (info->index.info == 0) {
		lerror("Not found %s section.\n", SEC_ULPATCH_INFO);
		return -EEXIST;
	}

	info->ulp_info = (void *)info->hdr
		+ info->sechdrs[info->index.info].sh_offset;

	/* found ".ulpatch.strtab" */
	info->index.ulp_strtab = find_sec(info, SEC_ULPATCH_STRTAB);
	const char *ulp_strtab = (void *)info->hdr
		+ info->sechdrs[info->index.ulp_strtab].sh_offset;

	err = parse_ulpatch_strtab(&info->ulp_strtab, ulp_strtab);
	if (err) {
		lerror("Failed parse ulpatch_strtab.\n");
		return -ENOENT;
	}

	/* Get patch type */
	if (!strcmp(info->ulp_strtab.patch_type, ULPATCH_TYPE_PATCH_STR))
		info->type = ULPATCH_TYPE_PATCH;
	else if (!strcmp(info->ulp_strtab.patch_type, ULPATCH_TYPE_FTRACE_STR))
		info->type = ULPATCH_TYPE_FTRACE;
	else {
		lerror("Unknown ulpatch type %s.\n", info->ulp_strtab.patch_type);
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

		const char *name = info->secstrings + shdr->sh_name;

		if (shdr->sh_type != SHT_NOBITS
			&& info->len < shdr->sh_offset + shdr->sh_size) {
			lerror("Patch len %lu truncated\n", info->len);
			return -ENOEXEC;
		}

		if ((shdr->sh_type == SHT_NOBITS || !strcmp(name, ".bss"))
		     && shdr->sh_size > 0) {
			lerror("Not support uninitialized variable yet.\n");
			return -EFAULT;
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

		ldebug("Rewrite section hdr %s sh_addr %Lx\n", name, shdr->sh_addr);
	}

	/* Track but don't keep info or other sections. */
	info->sechdrs[info->index.info].sh_flags &= ~(unsigned long)SHF_ALLOC;
	info->sechdrs[info->index.info].sh_flags |= SHF_RELA_LIVEPATCH;

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
			if (addr)
				goto found;
		}
	}

	ldebug("Not found %d in self ELF.\n", name);

	/* try find symbol address from @plt */
	if (task->fto_flag & FTO_SELF_PLT) {
		addr = objdump_elf_plt_symbol_address(task->objdump, name);
		if (addr)
			goto found;
	}

	ldebug("Not found %d in @plt.\n", name);

	/* try find symbol in libc.so */
	if (!sym && task->fto_flag & FTO_LIBC) {
		sym = find_symbol(task->libc_elf, name);
		if (sym) {
			addr = sym->sym.st_value;
			if (addr)
				goto found;
		}
	}

	ldebug("Not found %d in libc.\n", name);

	/* try find symbol in other libraries mapped in target process address
	 * space */
	if (!sym && task->fto_flag & FTO_VMA_ELF_SYMBOLS) {
		sym = task_vma_find_symbol((struct task *)task, name);
		if (sym) {
			addr = sym->sym.st_value;
			if (addr)
				goto found;
		}
	}

	if (!addr)
		lerror("Not find symbol %s in anywhere\n", name);

found:
	return addr;
}

/* Change all symbols so that st_value encodes the pointer directly. */
static int simplify_symbols(const struct load_info *info)
{
	unsigned long secbase;
	unsigned int i;
	int ret = 0;

	GElf_Shdr *symsec = &info->sechdrs[info->index.sym];

	/* need relocate sh_addr, because here is HOST task, not target task */
	GElf_Sym *sym = (void *)info->hdr + symsec->sh_addr - info->target_hdr;


	ldebug("sym = %lp + %lx - %lx, sh_offset %lx\n",
		info->hdr, symsec->sh_addr, info->target_hdr, symsec->sh_offset);

	for (i = 1; i < symsec->sh_size / sizeof(GElf_Sym); i++) {
		const char *name = info->strtab + sym[i].st_name;

		ldebug("symbol: %s, st_name: %d\n", name, sym[i].st_name);

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
			if (ret) {
				lerror("Unknown symbol %s's addr %Lx (err %d)\n",
					 name, symbol_addr, ret);
			}
			break;

		default:
			/* The address in the target process */
			secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
			sym[i].st_value += secbase;
			ldebug("In patch sym %s: secbase:0x%lx, st_value:0x%lx\n",
				name, secbase, sym[i].st_value);
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
			/* Not support 32bit SHT_REL yet */
			err = -ENOEXEC;
			break;
		} else if (info->sechdrs[i].sh_type == SHT_RELA)
			err = apply_relocate_add(info, info->sechdrs,
						info->strtab,
						info->index.sym, i);

		if (err < 0) {
			lerror("apply relocations failed.\n");
			break;
		}
	}

	return err;
}

static int post_relocation(const struct load_info *info)
{
	/* TODO: need add_allsyms() */

	return 0;
}

static int solve_patch_symbols(struct load_info *info)
{
	int i;
	struct task *task = info->target_task;
	struct symbol *sym;
	const char *dst_func, *src_func;
	GElf_Sym *sym_src_func = NULL;

	dst_func = info->ulp_strtab.dst_func;
	src_func = info->ulp_strtab.src_func;

	sym = task_vma_find_symbol(task, dst_func);
	if (!sym) {
		lerror("Couldn't found %s in target process.\n", dst_func);
		return -ENOENT;
	}

	GElf_Shdr *symsec = (GElf_Shdr *)&info->sechdrs[info->index.sym];
	GElf_Sym *syms = (GElf_Sym *)((void *)info->hdr + symsec->sh_offset);

	for (i = 0; i < symsec->sh_size / sizeof(GElf_Sym); i++) {
		GElf_Sym *sym = &syms[i];
		char *name = info->strtab + sym->st_name;
		ldebug("patch: %s, %d\n", name, sym->st_name);

		if (!strcmp(src_func, name))
			sym_src_func = sym;
	}

	if (!sym_src_func) {
		lerror("Couldn't found %s in target process.\n", src_func);
		return -ENOENT;
	}

	info->ulp_info->target_func_addr = sym->sym.st_value;
	info->ulp_info->patch_func_addr = sym_src_func->st_value;
	/* Replace from start of target function */
	info->ulp_info->virtual_addr = info->ulp_info->target_func_addr;

	ldebug("Found %s symbol address %#016lx.\n", dst_func, info->ulp_info->target_func_addr);
	ldebug("Found %s symbol address %#016lx.\n", src_func, info->ulp_info->patch_func_addr);
	return 0;
}

static int kick_target_process(const struct load_info *info)
{
	ssize_t n;
	int err = 0;
	struct task *task = info->target_task;
	unsigned long target_hdr = info->target_hdr;
	size_t insn_sz = 0;

#if defined(__x86_64__)
	union text_poke_insn insn;
	const char __unused *new_insn = NULL;
	new_insn = ulpatch_jmpq_replace(&insn, info->ulp_info->virtual_addr,
					info->ulp_info->patch_func_addr);
	insn_sz = CALL_INSN_SIZE;
#else
	lerror("not support expect x86_64 yet.\n");
	exit(1);
#endif

	n = memcpy_from_task(task, &info->ulp_info->orig_value,
				info->ulp_info->virtual_addr, insn_sz);
	if (n < insn_sz) {
		lerror("Backup original instructions failed.\n");
		/* TODO */
	}

	/* copy patch to target address space */
	n = memcpy_to_task(task, target_hdr, info->hdr, info->len);
	if (n < info->len) {
		lerror("failed kick target process.\n");
		err = -ENOEXEC;
	}

	task_attach(task->pid);

#if defined(__x86_64__)
	n = memcpy_to_task(task, info->ulp_info->virtual_addr, (void *)new_insn, insn_sz);
	if (n < insn_sz) {
		lerror("failed kick target process.\n");
		err = -ENOEXEC;
	}
#endif

	task_detach(task->pid);

	return err;
}

static int load_patch(struct load_info *info)
{
	long err = 0;

	err = setup_load_info(info);
	if (err)
		goto free_copy;

	/* May be there are some blacklists and sign check */

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

	err = solve_patch_symbols(info);
	if (err < 0)
		goto free_copy;

	err = kick_target_process(info);
	if (err < 0)
		goto free_copy;

free_copy:
	release_load_info(info);
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

	err = alloc_patch_file(obj_file, obj_to, &info);
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
		release_load_info(&info);
		return err;
	}

	err = load_patch(&info);
	if (err) {
		delete_mmap_vma_file(task, &info);
		release_load_info(&info);
		return err;
	}

	return 0;
}

/* delete last patched patch, so, don't need any other arguments */
int delete_patch(struct task *task)
{
	// TODO:

	return 0;
}

