// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <elf/elf_api.h>
#include <patch/patch.h>

#include <tests/test_api.h>


#define STATIC_FUNC_FN	test_static_func
static __unused void STATIC_FUNC_FN(void)
{
}

TEST(Ftrace,	elf_static_func_addr,	0)
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
		if (ret == -1)
			exit(1);
	} else if (pid > 0) {

		task_wait_wait(&waitqueue);

		struct symbol *sym;
		struct task_struct *task = open_task(pid, FTO_VMA_ELF_FILE);
		unsigned long memaddr = (unsigned long)STATIC_FUNC_FN;
		int pagesize = getpagesize();

		sym = find_symbol(task->exe_elf, __stringify(STATIC_FUNC_FN), STT_FUNC);
		if (!sym) {
			lerror("Not found %s.\n", __stringify(STATIC_FUNC_FN));
			ret = -1;
			goto out;
		}

		linfo("%s: st_value %lx, %lx\n",
			__stringify(STATIC_FUNC_FN), sym->sym.st_value, memaddr);

		/* st_value MUST equal to ELF address */
		if (sym->sym.st_value == memaddr) {
			ret = 0;
		} else {
			linfo(" %s's st_value %lx != %lx\n",
				__stringify(STATIC_FUNC_FN), sym->sym.st_value,
				memaddr);
			/**
			 * Because the load address and the address of the
			 * symbol in the ELF file are not absolutely equal,
			 * there is an offset relationship.
			 *
			 * This offset must be page aligned.
			 */
			unsigned long off = memaddr - sym->sym.st_value;
			if (off % pagesize)
				ret = -1;
			else
				ret = 0;
		}

out:
		task_wait_trigger(&waitqueue);

		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
		close_task(task);
	} else
		lerror("fork(2) error.\n");

	task_wait_destroy(&waitqueue);
	return ret;
}

TEST(Ftrace,	elf_global_func_addr,	0)
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
	} else if (pid > 0) {

		task_wait_wait(&waitqueue);

		struct symbol *sym;
		struct task_struct *task = open_task(pid, FTO_VMA_ELF_FILE);
		int pagesize = getpagesize();
		unsigned long memaddr;

		memaddr = (unsigned long)PRINTER_FN;
		/* Test1:
		 * Try find global function
		 */
		sym = find_symbol(task->exe_elf, __stringify(PRINTER_FN), STT_FUNC);
		if (!sym) {
			lerror("Not found %s.\n", __stringify(PRINTER_FN));
			ret = -1;
			goto out;
		}

		linfo("%s: st_value %lx, %lx\n",
			__stringify(PRINTER_FN), sym->sym.st_value, memaddr);

		/* st_value MUST equal to ELF address */
		if (sym->sym.st_value == memaddr) {
			ret = 0;
		} else {
			linfo(" %s's st_value %lx != %lx\n",
				__stringify(STATIC_FUNC_FN), sym->sym.st_value,
				memaddr);
			/**
			 * Because the load address and the address of the
			 * symbol in the ELF file are not absolutely equal,
			 * there is an offset relationship.
			 *
			 * This offset must be page aligned.
			 */
			unsigned long off = memaddr - sym->sym.st_value;
			if (off % pagesize)
				ret = -1;
			else
				ret = 0;
		}

		/* Test2:
		 * Try find libc function
		 */
		/* call it, make PLT/GOT done */
		LIBC_PUTS_FN(__stringify(LIBC_PUTS_FN));
		memaddr = (unsigned long)LIBC_PUTS_FN;

		sym = find_symbol(task->exe_elf, __stringify(LIBC_PUTS_FN), STT_FUNC);
		if (!sym) {
			lerror("Not found %s.\n", __stringify(LIBC_PUTS_FN));
			ret = -1;
			goto out;
		}

		linfo("%s: st_value %lx, %lx\n",
			__stringify(LIBC_PUTS_FN), sym->sym.st_value, memaddr);

		/* st_value MUST equal to ELF address */
		if (sym->sym.st_value == memaddr) {
			ret = 0;
		} else {
			linfo(" %s's st_value %lx != %lx\n",
				__stringify(STATIC_FUNC_FN), sym->sym.st_value,
				memaddr);
			/**
			 * Because the load address and the address of the
			 * symbol in the ELF file are not absolutely equal,
			 * there is an offset relationship.
			 *
			 * This offset must be page aligned.
			 */
			unsigned long off = memaddr - sym->sym.st_value;
			if (off % pagesize) {
#if defined(__aarch64__)
				/**
				 * TODO: st_value == 0 in aarch64?
				 */
				if (sym->sym.st_value == 0)
					ret = 0;
#else
				ret = -1;
#endif
			} else
				ret = 0;
		}

out:
		task_wait_trigger(&waitqueue);

		waitpid(pid, &status, __WALL);
		if (status != 0)
			ret = -EINVAL;
		close_task(task);
	} else
		lerror("fork(2) error.\n");

	task_wait_destroy(&waitqueue);
	return ret;
}

TEST(Ftrace,	elf_libc_func_addr,	0)
{
	int ret = -1;
	int status = 0;
	struct task_wait waitqueue;

	task_wait_init(&waitqueue, NULL);

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			(char*)ulpatch_test_path,
			"--role", "sleeper,trigger,printer,wait",
			"--msgq", waitqueue.tmpfile,
			NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	} else if (pid > 0) {

		task_wait_wait(&waitqueue);

		struct symbol *sym;
		struct task_struct *task = open_task(pid, FTO_VMA_ELF_FILE);

#ifndef LIBC_PUTS_FN
# error "No macro LIBC_PUTS_FN"
#endif
		LIBC_PUTS_FN(__stringify(LIBC_PUTS_FN));

		sym = find_symbol(task->libc_elf, __stringify(LIBC_PUTS_FN), STT_FUNC);
		if (!sym) {
			lerror("Not found %s.\n", __stringify(LIBC_PUTS_FN));
			ret = -1;
			goto out;
		}

		linfo("%s: st_value %lx, %p\n",
			__stringify(LIBC_PUTS_FN), sym->sym.st_value, LIBC_PUTS_FN);

		/* st_value not equal to ELF address in libc */
		if (sym->sym.st_value == (unsigned long)LIBC_PUTS_FN) {
			lerror(" %s's st_value %lx != %p\n",
				__stringify(LIBC_PUTS_FN), sym->sym.st_value, LIBC_PUTS_FN);
			ret = -1;
		} else {
			ret = 0;
		}

out:
		task_wait_trigger(&waitqueue);

		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
		close_task(task);
	} else {
		lerror("fork(2) error.\n");
	}

	task_wait_destroy(&waitqueue);

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
	} else if (pid > 0) {

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
	} else {
		lerror("fork(2) error.\n");
	}

	task_wait_destroy(&waitqueue);

	return ret;
}

TEST(Ftrace,	init_patch,	TEST_SKIP_RET)
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

TEST(Ftrace,	find_task_symbol_list,	0)
{
	return test_task_patch(FTO_ULFTRACE, find_task_symbol);
}

TEST(Ftrace,	find_task_symbol_value,	0)
{
	int ret = 0;
	int status = 0;
	pid_t pid;

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

	} else if (pid > 0) {

		int fd = -1, i, rslt;

		/**
		 * Wait for server init done. this method is not perfect.
		 */
		usleep(10000);

		struct task_struct *task = open_task(pid, FTO_ULFTRACE);

		dump_task_vmas(task, true);

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
	}

	task_wait_destroy(&waitqueue);

	return ret;
}

