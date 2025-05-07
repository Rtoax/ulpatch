// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>

#include <utils/log.h>
#include <utils/list.h>
#include <task/task.h>
#include <tests/test-api.h>


TEST(Task_sym, for_each, 0)
{
	struct task_struct *task;
	struct task_sym *tsym;

	task = open_task(getpid(), FTO_ULPATCH);

	for (tsym = next_task_sym(task, NULL); tsym;
	     tsym = next_task_sym(task, tsym))
	{
		ulp_info("TSYM: %s 0x%016lx\n", tsym->name, tsym->addr);
		if (!list_empty(&tsym->list_name.head)) {
			struct task_sym *s, *tmp;
			list_for_each_entry_safe(s, tmp,
			    &tsym->list_name.head, list_name.node) {
				ulp_info("TSYM: SUB %s 0x%016lx\n", s->name,
					 s->addr);
			}
		}
	}

	for (tsym = next_task_addr(task, NULL); tsym;
	     tsym = next_task_addr(task, tsym))
	{
		ulp_info("TADDR: 0x%016lx %s\n", tsym->addr, tsym->name);
		if (!list_empty(&tsym->list_addr.head)) {
			struct task_sym *s, *tmp;
			list_for_each_entry_safe(s, tmp,
			    &tsym->list_addr.head, list_addr.node) {
				ulp_info("TADDR: SUB 0x%016lx %s\n", s->addr,
					 s->name);
			}
		}
	}

	return close_task(task);
}

static int __task_resolve_sym(struct task_struct *task,
			      unsigned long real_addr, char *name)
{
	int ret = 0;
	struct task_sym *tsym;
	const struct task_sym **extras = NULL;
	unsigned long addr = 0, extra_addr1 = 0;
	size_t ie, nr_extras;


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
	if (unlikely(ret))
		ulp_error("%s: find %lx, real %lx, extra %ld (addr %lx)\n",
			  name, addr, real_addr, nr_extras, extra_addr1);
	return ret;
}

TEST(Task_sym, find_task_symbol_value, 0)
{
	int i, ret = 0;
	struct task_struct *task;

	task = open_task(getpid(), FTO_VMA_ELF_FILE);

#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wuninitialized"
#elif defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
	for (i = 0; i < nr_test_symbols(); i++)
		ret += __task_resolve_sym(task, test_symbols[i].addr,
				   test_symbols[i].sym);
#if defined(__GNUC__)
# pragma GCC diagnostic pop
#elif defined(__clang__)
# pragma clang diagnostic pop
#endif
	close_task(task);
	return ret;
}

