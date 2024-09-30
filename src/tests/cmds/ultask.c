// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <utils/log.h>
#include <utils/cmds.h>

#include <task/task.h>
#include <tests/test-api.h>

TEST_STUB(cmds_ultask);


TEST(ultask, version, 0)
{
	int argc = 2;
	char *argv[] = {"ultask", "--version"};
	char *argv2[] = {"ultask", "-V"};
	return ultask(argc, argv) + ultask(argc, argv2);
}

TEST(ultask, help, 0)
{
	int argc = 2;
	char *argv[] = {"ultask", "--help"};
	char *argv2[] = {"ultask", "-h"};
	return ultask(argc, argv) + ultask(argc, argv2);
}

TEST(ultask, info, 0)
{
	int ret;
	int verbose = get_verbose();

	int argc = 2;
	char *argv[] = {"ultask", "--info"};
	int argc2 = 3;
	char *argv2[] = {"ultask", "-vvvv", "--info"};

	ret = ultask(argc, argv) + ultask(argc2, argv2);

	enable_verbose(verbose);
	return ret;
}

TEST(ultask, dump, 0)
{
	int ret = 0;
	struct task_struct *task;
	char s_pid[64], s_dump[128], s_ofile[64];
	int argc;

	task = open_task(getpid(), FTO_NONE);

	memset(s_pid, 0x0, sizeof(s_pid));
	sprintf(s_pid, "%d", getpid());

	/**
	 * Dump memory to file
	 */
	memset(s_dump, 0x0, sizeof(s_dump));
	memset(s_ofile, 0x0, sizeof(s_ofile));
	sprintf(s_dump, "addr=0x%lx,size=0x%lx", (unsigned long)s_dump, sizeof(s_dump));
	sprintf(s_ofile, "ultask.dump_mem-%d.dat", getpid());

	argc = 7;
	char *argv_mem[] = {
		"ultask",
		"--pid", s_pid,
		"--dump", s_dump,
		"--output", s_ofile
	};

	ret += ultask(argc, argv_mem);

	/**
	 * Dump vma to file
	 */
	memset(s_dump, 0x0, sizeof(s_dump));
	memset(s_ofile, 0x0, sizeof(s_ofile));
	sprintf(s_dump, "vma,addr=0x%lx", (unsigned long)ultask);
	sprintf(s_ofile, "ultask.dump_vma-%d.dat", getpid());

	argc = 7;
	char *argv_vma[] = {
		"ultask",
		"--pid", s_pid,
		"--dump", s_dump,
		"--output", s_ofile
	};

	ret += ultask(argc, argv_vma);

	/**
	 * Disasm text
	 */
	memset(s_dump, 0x0, sizeof(s_dump));
	sprintf(s_dump, "disasm,addr=0x%lx,size=0x64", (unsigned long)ultask);

	argc = 5;
	char *argv_disasm[] = {
		"ultask",
		"--pid", s_pid,
		"--dump", s_dump,
	};

	ret += ultask(argc, argv_disasm);

	ret += close_task(task);

	return ret;
}
