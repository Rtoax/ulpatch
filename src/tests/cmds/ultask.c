// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024 Rong Tao */
#include <sys/wait.h>

#include <utils/log.h>
#include <utils/cmds.h>

#include <task/task.h>
#include <utils/disasm.h>

#include <tests/test-api.h>

TEST_STUB(cmds_ultask);

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
	fremove(s_ofile);

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
	fremove(s_ofile);

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

static int jmp_src_func(void)
{
	/* Store jmp table entry */
	char __unused buf[sizeof(struct jmp_table_entry)] = {0};
#define JMP_SRC_RET	-1
	return JMP_SRC_RET;
}

static int jmp_dst_func(void)
{
	char buf[] = {"Hello, ULPatch\n"};
	puts(buf);
#define JMP_DST_RET	-1
	return JMP_DST_RET;
}

TEST(ultask, jmp, 0)
{
	int ret = 0, test_ret;
	struct task_struct *task;
	char s_pid[64], s_jmp[128];
	int argc;

	task = open_task(getpid(), FTO_NONE);

	memset(s_pid, 0x0, sizeof(s_pid));
	sprintf(s_pid, "%d", getpid());

	memset(s_jmp, 0x0, sizeof(s_jmp));
	sprintf(s_jmp, "from=0x%lx,to=0x%lx", (unsigned long)jmp_src_func,
			(unsigned long)jmp_dst_func);

	fprintf(stdout, "--jmp %s\n", s_jmp);

	argc = 5;
	char *argv[] = {
		"ultask",
		"--pid", s_pid,
		"--jmp", s_jmp,
	};

	test_ret = jmp_src_func();
	if (test_ret != JMP_SRC_RET)
		ret++;

	fdisasm_arch(stdout, "jmp_src_func: ", 0, (void *)jmp_src_func,
	      (unsigned long)(jmp_dst_func - jmp_src_func));
	fdisasm_arch(stdout, "jmp_dst_func: ", 0, (void *)jmp_dst_func, 32);

	ret += ultask(argc, argv);

	fdisasm_arch(stdout, "jmp_src_func: ", 0, (void *)jmp_src_func,
	      (unsigned long)(jmp_dst_func - jmp_src_func));
	fdisasm_arch(stdout, "jmp_dst_func: ", 0, (void *)jmp_dst_func, 32);

	test_ret = jmp_src_func();
	if (test_ret != JMP_DST_RET)
		ret++;

	ret += close_task(task);

	return ret;
}

TEST(ultask, symbols, 0)
{
	int ret = 0;
	struct task_struct *task;
	char s_pid[64];

	task = open_task(getpid(), FTO_NONE);

	memset(s_pid, 0x0, sizeof(s_pid));
	sprintf(s_pid, "%d", getpid());

	int argc = 4;
	char *argv[] = {
		"ultask",
		"--pid", s_pid,
		"--symbols"
	};

	char *argv2[] = {
		"ultask",
		"--pid", s_pid,
		"--syms"
	};

	ret += ultask(argc, argv);
	ret += ultask(argc, argv2);

	ret += close_task(task);

	return ret;
}

TEST(ultask, vma, 0)
{
	int ret = 0;
	struct task_struct *task;
	char s_pid[64];

	task = open_task(getpid(), FTO_NONE);

	memset(s_pid, 0x0, sizeof(s_pid));
	sprintf(s_pid, "%d", getpid());

	int argc = 4;
	char *argv[] = {
		"ultask",
		"--pid", s_pid,
		"--vmas"
	};

	int argc2 = 5;
	char *argv2[] = {
		"ultask",
		"--pid", s_pid,
		"--vmas",
		"--verbose",
	};

	ret += ultask(argc, argv);
	ret += ultask(argc2, argv2);

	ret += close_task(task);

	return ret;
}

TEST(ultask, misc, 0)
{
	int ret = 0;
	struct task_struct *task;
	char s_pid[64];

	task = open_task(getpid(), FTO_NONE);

	memset(s_pid, 0x0, sizeof(s_pid));
	sprintf(s_pid, "%d", getpid());

	int argc = 7;
	char *argv[] = {
		"ultask",
		"--pid", s_pid,
		"--fds",
		"--threads",
		"--auxv",
		"--status",
	};

	ret += ultask(argc, argv);

	ret += close_task(task);

	return ret;
}

TEST(ultask, mmap, 0)
{
	int err = 0;
	char buffer[PATH_MAX];
	char *f_name;
	char s_pid[64], s_map[PATH_MAX], s_maps[PATH_MAX];
	char s_tcwd[PATH_MAX], *tcwd;
	char s_tmfile[PATH_MAX];
	int status = 0;
	struct task_notify notify;

	task_notify_init(&notify, NULL);

	pid_t pid = fork();
	if (pid == 0) {
		int ret = -1;
		char *argv[] = {
			(char*)ulpatch_test_path,
			"--role", "sleeper,trigger,sleeper,wait",
			"--msgq", notify.tmpfile,
			NULL
		};

		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	}

	/* Parent */

	/* Create tmp file */
	tcwd = get_proc_pid_cwd(pid, s_tcwd, sizeof(s_tcwd));
	snprintf(s_tmfile, PATH_MAX, "%s/ultask-map-XXXXXX", tcwd);
	f_name = fmktempname(buffer, PATH_MAX, s_tmfile);
	if (!f_name)
		return -1;

	if (ftouch(f_name, 64))
		return -1;

	printf("fmktempfile: %s\n", f_name);

	if (!fexist(f_name)) {
		err = -EEXIST;
		goto done;
	}

	memset(s_pid, 0x0, sizeof(s_pid));
	sprintf(s_pid, "%d", pid);

	memset(s_map, 0x0, sizeof(s_map));
	sprintf(s_map, "file=%s", f_name);

	task_notify_wait(&notify);

	int argc = 6;
	char *argv[] = {
		"ultask",
		"--pid", s_pid,
		"--map", s_map,
		"--verbose",
	};

	fprintf(stdout, "ultask --pid %s --map %s\n", s_pid, s_map);
	err += ultask(argc, argv);

	/* Test ro */
	memset(s_map, 0x0, sizeof(s_map));
	sprintf(s_map, "file=%s,ro", f_name);
	fprintf(stdout, "ultask --pid %s --map %s\n", s_pid, s_map);
	err += ultask(argc, argv);

	/* Test ro and noexec */
	memset(s_map, 0x0, sizeof(s_map));
	sprintf(s_map, "file=%s,ro,noexec", f_name);
	fprintf(stdout, "ultask --pid %s --map %s\n", s_pid, s_map);
	err += ultask(argc, argv);

	/* Test addr */
	memset(s_map, 0x0, sizeof(s_map));
	/* hope addr 0x10000 is not in use */
	sprintf(s_map, "file=%s,ro,noexec,addr=0x10000", f_name);
	fprintf(stdout, "ultask --pid %s --map %s\n", s_pid, s_map);
	err += ultask(argc, argv);

	sprintf(s_maps, "/proc/%d/maps", pid);
	fprint_file(stdout, s_maps);

	task_notify_trigger(&notify);

	waitpid(pid, &status, __WALL);
	if (status != 0) {
		err = -EINVAL;
	}

	task_notify_destroy(&notify);

done:
	unlink(f_name);
	return err;
}

TEST(ultask, mprotect, 0)
{
	int err = 0;
	char buffer[PATH_MAX];
	char *f_name;
	char s_pid[64], s_map[PATH_MAX], s_mprotect[PATH_MAX], s_maps[PATH_MAX];
	char s_tcwd[PATH_MAX], *tcwd;
	char s_tmfile[PATH_MAX];
	int status = 0;
	struct task_notify notify;

	task_notify_init(&notify, NULL);

	pid_t pid = fork();
	if (pid == 0) {
		int ret = -1;
		char *argv[] = {
			(char*)ulpatch_test_path,
			"--role", "sleeper,trigger,sleeper,wait",
			"--msgq", notify.tmpfile,
			NULL
		};

		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	}

	/* Parent */

	/* Create tmp file */
	tcwd = get_proc_pid_cwd(pid, s_tcwd, sizeof(s_tcwd));
	snprintf(s_tmfile, PATH_MAX, "%s/ultask-mprotect-XXXXXX", tcwd);
	f_name = fmktempname(buffer, PATH_MAX, s_tmfile);
	if (!f_name)
		return -1;

	task_notify_wait(&notify);

	unsigned long addr = 0x100000;
	unsigned long len = ulp_page_size() * 10;

	/* Need two page at least */
	if (ftouch(f_name, len))
		return -1;

	printf("fmktempfile: %s\n", f_name);

	if (!fexist(f_name)) {
		err = -EEXIST;
		goto done;
	}

	memset(s_pid, 0x0, sizeof(s_pid));
	sprintf(s_pid, "%d", pid);

	memset(s_map, 0x0, sizeof(s_map));
	sprintf(s_map, "file=%s,addr=0x%lx", f_name, addr);

	/* mmap a new region to test mprotect */
	{
		int argc = 6;
		char *argv[] = {
			"ultask",
			"--pid", s_pid,
			"--map", s_map,
			"--verbose",
		};

		fprintf(stdout, "ultask --pid %s --map %s\n", s_pid, s_map);
		err += ultask(argc, argv);
	}

	/* default prot is none */
	memset(s_mprotect, 0x0, sizeof(s_mprotect));
	sprintf(s_mprotect, "addr=0x%lx,len=0x%x", addr, ulp_page_size());

	int argc = 6;
	char *argv[] = {
		"ultask",
		"--pid", s_pid,
		"--mprotect", s_mprotect,
		"--verbose",
	};

	fprintf(stdout, "ultask --pid %s --mprotect %s\n", s_pid, s_mprotect);
	err += ultask(argc, argv);

	/* read */
	memset(s_mprotect, 0x0, sizeof(s_mprotect));
	addr += ulp_page_size();
	sprintf(s_mprotect, "addr=0x%lx,len=0x%x,read", addr, ulp_page_size());
	fprintf(stdout, "ultask --pid %s --mprotect %s\n", s_pid, s_mprotect);
	err += ultask(argc, argv);

	/* write */
	memset(s_mprotect, 0x0, sizeof(s_mprotect));
	addr += ulp_page_size();
	sprintf(s_mprotect, "addr=0x%lx,len=0x%x,write", addr, ulp_page_size());
	fprintf(stdout, "ultask --pid %s --mprotect %s\n", s_pid, s_mprotect);
	err += ultask(argc, argv);

	/* exec */
	memset(s_mprotect, 0x0, sizeof(s_mprotect));
	addr += ulp_page_size();
	sprintf(s_mprotect, "addr=0x%lx,len=0x%x,exec", addr, ulp_page_size());
	fprintf(stdout, "ultask --pid %s --mprotect %s\n", s_pid, s_mprotect);
	err += ultask(argc, argv);

	/* read,write,exec */
	memset(s_mprotect, 0x0, sizeof(s_mprotect));
	addr += ulp_page_size();
	sprintf(s_mprotect, "addr=0x%lx,len=0x%x,read,write,exec", addr, ulp_page_size());
	fprintf(stdout, "ultask --pid %s --mprotect %s\n", s_pid, s_mprotect);
	err += ultask(argc, argv);

	/* write,exec */
	memset(s_mprotect, 0x0, sizeof(s_mprotect));
	addr += ulp_page_size();
	sprintf(s_mprotect, "addr=0x%lx,len=0x%x,write,exec", addr, ulp_page_size());
	fprintf(stdout, "ultask --pid %s --mprotect %s\n", s_pid, s_mprotect);
	err += ultask(argc, argv);

	sprintf(s_maps, "/proc/%d/maps", pid);
	fprint_file(stdout, s_maps);

	task_notify_trigger(&notify);

	waitpid(pid, &status, __WALL);
	if (status != 0) {
		err = -EINVAL;
	}

	task_notify_destroy(&notify);

done:
	unlink(f_name);
	return err;
}
