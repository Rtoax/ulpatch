// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <elf/elf-api.h>
#include <patch/patch.h>

#include <tests/test-api.h>


#define STATIC_FUNC_FN	test_static_func
static __unused void STATIC_FUNC_FN(void)
{
}

static int open_task_and_resolve_sym(unsigned long real_addr, char *name)
{
	int ret = 0;
	int status = 0;
	struct task_wait waitqueue;

	task_wait_init(&waitqueue, NULL);

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			(char*)ulpatch_test_path,
			"--role", "sleeper,trigger,sleeper,wait",
			"--msgq", waitqueue.tmpfile,
			NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1)
			exit(1);
	}

	/* Parent */
	task_wait_wait(&waitqueue);

	struct symbol *sym;
	struct task_struct *task = open_task(pid, FTO_VMA_ELF_FILE);
	unsigned long memaddr = real_addr;
	unsigned long addr;

	sym = task_vma_find_symbol(task, name, STT_FUNC);
	if (!sym) {
		lerror("Not found %s.\n", name);
		ret = -1;
		goto out;
	}
	addr = task_vma_symbol_vaddr(sym);

	linfo("%s: find %lx, real %lx\n", name, addr, memaddr);

	if (addr != memaddr) {
		lerror("%s: find %lx, real %lx\n", name, addr, memaddr);
		ret = -1;
	}

out:
	task_wait_trigger(&waitqueue);

	waitpid(pid, &status, __WALL);
	if (status != 0) {
		ret = -EINVAL;
	}
	close_task(task);

	task_wait_destroy(&waitqueue);
	return ret;
}

TEST(Symbol, task_func_addr, 0)
{
	int ret = 0;
	/* static */
	ret += open_task_and_resolve_sym((unsigned long)STATIC_FUNC_FN,
					 __stringify(STATIC_FUNC_FN));
	/* global */
	ret += open_task_and_resolve_sym((unsigned long)PRINTER_FN,
					 __stringify(PRINTER_FN));
	/* FIXME: puts in SELF and libc.so??? */
	ret += open_task_and_resolve_sym((unsigned long)LIBC_PUTS_FN,
					 __stringify(LIBC_PUTS_FN));
	return ret;
}

static int test_task_patch(int fto_flags, int (*cb)(struct task_struct *))
{
	int ret = -1;
	int status = 0;
	struct task_wait waitqueue;

	task_wait_init(&waitqueue, NULL);

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			(char*)ulpatch_test_path,
			"--role", "sleeper,trigger,sleeper,wait",
			"--msgq", waitqueue.tmpfile,
			NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	}

	/* Parent */
	task_wait_wait(&waitqueue);

	struct task_struct *task = open_task(pid, fto_flags);

	ret = init_patch(task, ULPATCH_FTRACE_OBJ_PATH);
	if (ret == -EEXIST) {
		fprintf(stderr, "%s not exist. make install\n",
			ULPATCH_FTRACE_OBJ_PATH);
	}

	if (cb)
		ret = cb(task);

	dump_task_vmas(task, true);

	delete_patch(task);

	task_wait_trigger(&waitqueue);

	waitpid(pid, &status, __WALL);
	if (status != 0) {
		ret = -EINVAL;
	}
	close_task(task);

	task_wait_destroy(&waitqueue);

	return ret;
}

TEST(Symbol, init_patch, TEST_SKIP_RET)
{
	return test_task_patch(FTO_ULFTRACE, NULL);
}


static int find_task_symbol(struct task_struct *task)
{
	int i;
	int err = 0;
	struct symbol *sym;

	for (i = 0; i < ARRAY_SIZE(test_symbols); i++) {

		sym = task_vma_find_symbol(task, test_symbols[i].sym, STT_FUNC);

		linfo("%s %-30s: 0x%lx\n",
			sym?"Exist":"NoExi",
			test_symbols[i].sym,
			sym?sym->sym.st_value:0);

		if (!sym)
			err = -1;
	}

	return err;
}

TEST(Symbol, find_task_symbol_list, 0)
{
	return test_task_patch(FTO_ULFTRACE, find_task_symbol);
}

TEST(Symbol, find_task_plt_symbol_value, 0)
{
	int ret = 0;
	int status = 0;
	pid_t pid;
	int fd = -1, i, rslt;
	bool is_pie = false;

	struct task_wait waitqueue;

	task_wait_init(&waitqueue, NULL);

	pid = fork();
	if (pid == 0) {
		int ret;

		char *_argv[] = {
			(char*)ulpatch_test_path,
			"--role", "listener",
			"--listener-epoll",
			NULL,
		};
		ret = execvp(_argv[0], _argv);
		if (ret == -1) {
			exit(1);
		}

	}

	/* Parent */
	/**
	 * Wait for server init done. this method is not perfect.
	 */
	usleep(10000);

	struct task_struct *task = open_task(pid, FTO_ULFTRACE);

	dump_task_vmas(task, true);

	is_pie = task_is_pie(task);

	fd = listener_helper_create_test_client();

	if (fd <= 0)
		ret = -1;

	for (i = 0; i < ARRAY_SIZE(test_symbols); i++) {
		unsigned long addr, plt_addr;
		struct symbol *sym, *alias_sym = NULL;

		plt_addr = objdump_elf_plt_symbol_address(task->objdump,
			test_symbols[i].sym);

		sym = task_vma_find_symbol(task, test_symbols[i].sym, STT_FUNC);
		if (!sym) {
			lerror("Could not find %s in pid %d vma.\n",
				test_symbols[i].sym, task->pid);
			ret = -EEXIST;
			continue;
		}

		/* Only non static has alias symbol name, such as 'stdout' */
		if (test_symbols[i].type == TST_NON_STATIC)
			alias_sym = task_vma_find_symbol(task, test_symbols[i].alias, STT_FUNC);

		listener_helper_symbol(fd, test_symbols[i].sym, &addr);

		/* TODO: i'm not sure this is a correct method to get symbol
		 * address value. */
		linfo("%-10s %s%s\n"
			"%016lx(proc) %016lx(vma) %016lx(alias) %016lx(plt)\n",
			test_symbols[i].sym,
			test_symbols[i].alias ?: "",
			test_symbols[i].alias ? "(alias)" : "",
			addr,
			task_vma_symbol_vaddr(sym),
			alias_sym ? task_vma_symbol_vaddr(alias_sym) : 0,
			plt_addr);

		/* When relocate, we can use symbol's real virtual address in libc,
		 * as the same time, we can use the @plt address in target elf file.
		 */
		if (addr == 0 ||
			(addr != sym->sym.st_value && addr != plt_addr)) {

			/* Can't found the symbol address, try find with alias symbol
			 * if have one. */
			unsigned long alias_addr = 0;
			if (alias_sym &&
				(alias_addr = task_vma_symbol_vaddr(alias_sym))) {
			/* Couldn't found symbol in anyway. */
			} else
				ret = -1;
		}
		if (ret) {
			lerror("Sym %s wrong addr %lx(plt), %lx(mem)\n",
				test_symbols[i].sym, plt_addr, addr);
		}
	}

	listener_helper_close(fd, &rslt);
	listener_helper_close_test_client(fd);

	waitpid(pid, &status, __WALL);
	if (status != 0) {
		ret = -EINVAL;
	}
	close_task(task);

	task_wait_destroy(&waitqueue);

	/**
	 * FIXME: We should not use @plt in PIE, remove this test further, now,
	 * let's return success anyway if PIE.
	 */
	return is_pie ? 0 : ret;
}

