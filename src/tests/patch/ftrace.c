// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <elf/elf_api.h>
#include <patch/patch.h>

#include "../test_api.h"

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
			(char*)upatch_test_path,
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
		struct task *task = open_task(pid, FTO_SELF);

		sym = find_symbol(task->exe_elf, __stringify(STATIC_FUNC_FN));
		if (!sym) {
			lerror("Not found %s.\n", __stringify(STATIC_FUNC_FN));
			ret = -1;
			goto out;
		}

		linfo("%s: st_value %lx, %p\n",
			__stringify(STATIC_FUNC_FN), sym->sym.st_value, STATIC_FUNC_FN);

		/* st_value MUST equal to ELF address */
		if (sym->sym.st_value == (unsigned long)STATIC_FUNC_FN) {
			ret = 0;
		} else {
			lerror(" %s's st_value %lx != %p\n",
				__stringify(STATIC_FUNC_FN), sym->sym.st_value, STATIC_FUNC_FN);
			ret = -1;
		}

out:
		task_wait_trigger(&waitqueue);

		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
		free_task(task);
	} else {
		lerror("fork(2) error.\n");
	}

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
			(char*)upatch_test_path,
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
		struct task *task = open_task(pid, FTO_SELF);

		/* Test1:
		 * Try find global function
		 */
		sym = find_symbol(task->exe_elf, __stringify(PRINTER_FN));
		if (!sym) {
			lerror("Not found %s.\n", __stringify(PRINTER_FN));
			ret = -1;
			goto out;
		}

		linfo("%s: st_value %lx, %p\n",
			__stringify(PRINTER_FN), sym->sym.st_value, PRINTER_FN);

		/* st_value MUST equal to ELF address */
		if (sym->sym.st_value == (unsigned long)PRINTER_FN) {
			ret = 0;
		} else {
			lerror(" %s's st_value %lx != %p\n",
				__stringify(STATIC_FUNC_FN), sym->sym.st_value, STATIC_FUNC_FN);
			ret = -1;
		}

		/* Test2:
		 * Try find libc function
		 */
		// call it, make PLT/GOT done
		LIBC_PUTS_FN(__stringify(LIBC_PUTS_FN));

		sym = find_symbol(task->exe_elf, __stringify(LIBC_PUTS_FN));
		if (!sym) {
			lerror("Not found %s.\n", __stringify(LIBC_PUTS_FN));
			ret = -1;
			goto out;
		}

		linfo("%s: st_value %lx, %p\n",
			__stringify(LIBC_PUTS_FN), sym->sym.st_value, LIBC_PUTS_FN);

		/* st_value MUST equal to ELF address */
		if (sym->sym.st_value == (unsigned long)LIBC_PUTS_FN) {
			ret = 0;
		} else {
			lerror(" %s's st_value %lx != %p\n",
				__stringify(STATIC_FUNC_FN), sym->sym.st_value, STATIC_FUNC_FN);
			ret = -1;
		}

out:
		task_wait_trigger(&waitqueue);

		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
		free_task(task);
	} else {
		lerror("fork(2) error.\n");
	}

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
			(char*)upatch_test_path,
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
		struct task *task = open_task(pid, FTO_LIBC);

#ifndef LIBC_PUTS_FN
# error "No macro LIBC_PUTS_FN"
#endif
		LIBC_PUTS_FN(__stringify(LIBC_PUTS_FN));

		sym = find_symbol(task->libc_elf, __stringify(LIBC_PUTS_FN));
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
		free_task(task);
	} else {
		lerror("fork(2) error.\n");
	}

	task_wait_destroy(&waitqueue);

	return ret;
}

static int test_task_patch(int fto_flags, int (*cb)(struct task *))
{
	int ret = -1;
	int status = 0;
	struct task_wait waitqueue;

	task_wait_init(&waitqueue, NULL);

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			(char*)upatch_test_path,
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

		struct task *task = open_task(pid, fto_flags);

		ret = init_patch(task, UPATCH_FTRACE_OBJ_PATH);
		if (ret == -EEXIST) {
			fprintf(stderr, "%s not exist. make install\n",
				UPATCH_FTRACE_OBJ_PATH);
		}

		if (cb)
			ret = cb(task);

		dump_task_vmas(task);

		delete_patch(task);

		task_wait_trigger(&waitqueue);

		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
		free_task(task);
	} else {
		lerror("fork(2) error.\n");
	}

	task_wait_destroy(&waitqueue);

	return ret;
}

TEST(Ftrace,	init_patch,	0)
{
	return test_task_patch(FTO_PROC, NULL);
}


static int find_task_symbol(struct task *task)
{
	int i;
	int err = 0;
	struct symbol *sym;

	for (i = 0; i < ARRAY_SIZE(test_symbols); i++) {

		sym = task_vma_find_symbol(task, test_symbols[i].sym);

		linfo("%s %-30s: 0x%lx\n",
			sym?"Exist":"NoExi",
			test_symbols[i].sym,
			sym?sym->sym.st_value:0);

		if (!sym)
			err = -1;
	}

	return err;
}

TEST(Ftrace,	find_task_symbol,	0)
{
	return test_task_patch(FTO_FTRACE, find_task_symbol);
}

TEST(Ftrace,	find_vma_task_symbol,	0)
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
			(char*)upatch_test_path,
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

		struct task *task = open_task(pid, FTO_FTRACE);

		dump_task_vmas(task);

		fd = listener_helper_create_test_client();

		if (fd <= 0)
			ret = -1;

		for (i = 0; i < ARRAY_SIZE(test_symbols); i++) {
			unsigned long addr, plt_addr;
			struct symbol *sym;

			plt_addr = objdump_elf_plt_symbol_address(task->objdump,
				test_symbols[i].sym);

			sym = task_vma_find_symbol(task, test_symbols[i].sym);
			if (!sym) {
				lerror("Could not find %s in pid %d vma.\n",
					test_symbols[i].sym, task->pid);
				ret = -EEXIST;
				continue;
			}

			listener_helper_symbol(fd, test_symbols[i].sym, &addr);

			/**
			 * TODO
			 * I don't know why st_value in target vma not equal to addr in
			 * target task. did i miss some thing?
			 *
			 * I should make this test failed, ret = -1;
			 */
			linfo("%-10s: %lx vs %lx(vma) %lx(plt)\n",
				test_symbols[i].sym,
				addr,
				task_vma_symbol_value(sym),
				plt_addr);

			/* When relocate, we can use symbol's real virtual address in libc,
			 * as the same time, we can use the @plt address in target elf file.
			 */
			if (addr == 0 ||
				(addr != sym->sym.st_value && addr != plt_addr)) {

				/* Can't found the symbol address */
				ret = -1;
			}
		}

		listener_helper_close(fd, &rslt);
		listener_helper_close_test_client(fd);

		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
		free_task(task);
	}

	task_wait_destroy(&waitqueue);

	return ret;
}

