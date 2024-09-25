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

TEST_STUB(patch_symbol);

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

TEST(Patch_sym, init_patch, TEST_SKIP_RET)
{
	return test_task_patch(FTO_ULFTRACE, NULL);
}

static int find_task_symbol(struct task_struct *task)
{
	int i;
	int err = 0;
	struct task_sym *tsym;

	for (i = 0; i < nr_test_symbols(); i++) {
		tsym = find_task_sym(task, test_symbols[i].sym, NULL, NULL);
		ulp_info("%s %-30s: 0x%lx\n",
			tsym ? "Exist" : "NoExi",
			test_symbols[i].sym,
			tsym ? tsym->addr : 0);
		if (!tsym)
			err = -1;
	}
	return err;
}

TEST(Patch_sym, find_task_symbol_list, 0)
{
	return test_task_patch(FTO_ULFTRACE, find_task_symbol);
}

