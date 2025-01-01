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

TEST_STUB(task_vma);

TEST(Task, dump_vma, 0)
{
	struct task_struct *task = open_task(getpid(), FTO_NONE);
	dump_task_vmas(stdout, task, true);
	return close_task(task);
}

TEST(Task, for_each_vma, 0)
{
	struct task_struct *task = open_task(getpid(), FTO_NONE);
	struct vm_area_struct *vma;
	bool first_line = true;

	task_for_each_vma(vma, task) {
		print_vma(stdout, first_line, vma, true);
		first_line = false;
	}

	return close_task(task);
}

TEST(Task, find_vma, 0)
{
	int ret = 0;
	struct task_struct *task = open_task(getpid(), FTO_NONE);
	struct vm_area_struct *vma;
	bool first_line = true;

	task_for_each_vma(vma, task) {
		struct vm_area_struct *find = NULL;
		find = find_vma(task, vma->vm_start);
		if (!find) {
			ret = -1;
			goto failed;
		}
		print_vma(stdout, first_line, find, true);
		first_line = false;
	}

failed:
	close_task(task);
	return ret;
}

TEST(Task, dump_task_vma_to_file, 0)
{
	int ret = 0;
	struct task_struct *task = open_task(getpid(), FTO_NONE);
	unsigned long addr;
	struct vm_area_struct *vma;

	task_for_each_vma(vma, task) {
		/* Make sure the address is within the VMA range */
		addr = vma->vm_start;

		/* Only VDSO code is tested here, there is no need to test them
		 * all, right! Note that this test will overwrite vdso.so files
		 * in the current directory */
		char *vdso = "vdso.so";

		if (!strcmp(vma->name_, "[vdso]")) {
			dump_task_vma_to_file(vdso, task, addr);
			if (!fexist(vdso))
				ret++;
			fremove(vdso);
		}
	}

	ret += close_task(task);
	return ret;
}

