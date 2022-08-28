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
			(char*)elftools_test_path,
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
			(char*)elftools_test_path,
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
			(char*)elftools_test_path,
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
			(char*)elftools_test_path,
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

		ret = init_patch(task, ELFTOOLS_FTRACE_OBJ_PATH);
		if (ret == -EEXIST) {
			fprintf(stderr, "%s not exist. make install\n",
				ELFTOOLS_FTRACE_OBJ_PATH);
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

static const char *SYMBOLS[] = {
#define TEST_SYM(s) __stringify(s),
#define TEST_SYM_NON_STATIC(s)
#include "../test_symbols.h"
#undef TEST_SYM
#undef TEST_SYM_NON_STATIC
};

static int find_task_symbol(struct task *task)
{
	int i;
	int err = 0;
	struct symbol *sym;

	for (i = 0; i < ARRAY_SIZE(SYMBOLS); i++) {
		sym = task_vma_find_symbol(task, SYMBOLS[i]);

		linfo("%s %-30s: 0x%lx\n",
			sym?"Exist":"NoExi",
			SYMBOLS[i],
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

