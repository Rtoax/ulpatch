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


static int open_task_and_resolve_sym(unsigned long real_addr, char *name)
{
	int ret = 0;
	struct task_sym *tsym;
	const struct task_sym **extras = NULL;
	struct task_struct *task;
	unsigned long addr, extra_addr1 = 0;
	size_t ie, nr_extras;

	task = open_task(getpid(), FTO_VMA_ELF_FILE);

	tsym = find_task_sym(task, name, &extras, &nr_extras);
	if (!tsym) {
		ulp_error("Not found %s.\n", name);
		ret = -1;
		goto out;
	}
	addr = tsym->addr;

	ulp_info("%s: find %lx, real %lx, extra %ld\n", name, addr, real_addr,
		 nr_extras);

	if (addr != real_addr) {
		ulp_warning("%s: find %lx, real %lx\n", name, addr, real_addr);
		ret = -1;
	}

	if (nr_extras > 0) {
		for (ie = 0; ie < nr_extras; ie++) {
			if (extras[ie]->addr == real_addr) {
				ulp_warning("Match %s with extra symbol %s, "
					    "addr 0x%lx\n",
					    name, extras[ie]->name,
					    extras[ie]->addr);
				ret = 0;
				break;
			}
		}
		extra_addr1 = extras[0]->addr;
		free((void *)extras);
	}

out:
	close_task(task);
	if (unlikely(ret))
		ulp_error("%s: find %lx, real %lx, extra %ld (addr %lx)\n",
			  name, addr, real_addr, nr_extras, extra_addr1);
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

TEST(Symbol, find_task_symbol_list, 0)
{
	return test_task_patch(FTO_ULFTRACE, find_task_symbol);
}

TEST(Symbol, find_task_symbol_value, 0)
{
	int i, ret = 0;
	for (i = 0; i < nr_test_symbols(); i++)
		ret += open_task_and_resolve_sym(test_symbols[i].addr,
				   test_symbols[i].sym);
	return ret;
}

