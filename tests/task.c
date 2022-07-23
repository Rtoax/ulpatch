#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/task.h>

#include "test_api.h"

TEST(Task,	open_free,	0)
{
	struct task *task = open_task(getpid());

	return free_task(task);
}

TEST(Task,	open_failed,	-1)
{
	// Try to open pid 1 (systemd)
	// with 'sudo' it's will success
	struct task *task = open_task(0);

	return task?0:-1;
}

TEST(Task,	open_non_exist,	-1)
{
	// Try to open pid -1 (non exist)
	struct task *task = open_task(-1);

	return task?0:-1;
}

TEST(Task,	dump_task_vmas,	0)
{
	struct task *task = open_task(getpid());

	dump_task_vmas(task);

	return free_task(task);
}

TEST(Task,	attach_detach,	0)
{
	int ret = -1;
	int status = 0;

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			"sleep", "0.2", NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	} else if (pid > 0) {
		ret = task_attach(pid);
		ret = task_detach(pid);
		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
	} else {
		lerror("fork(2) error.\n");
	}

	return ret;
}

TEST(Task,	for_each_vma,	0)
{
	struct task *task = open_task(getpid());
	struct vma_struct *vma;

	task_for_each_vma(vma, task) {
		print_vma(vma);
	}

	return free_task(task);
}

TEST(Task,	find_vma,	0)
{
	int ret = 0;
	struct task *task = open_task(getpid());
	struct vma_struct *vma;

	task_for_each_vma(vma, task) {
		struct vma_struct *find = NULL;
		find = find_vma(task, vma->start);
		if (!find) {
			ret = -1;
			goto failed;
		}
		print_vma(find);
	}

failed:
	free_task(task);
	return ret;
}

TEST(Task,	copy_from_task,	0)
{
	char data[] = "ABCDEFG";
	char buf[64] = "XXXXXX";
	int ret = 0;
	int n;

	struct task *task = open_task(getpid());

	n = memcpy_from_task(task, buf, (unsigned long)data, strlen(data) + 1);
	ldebug("memcpy_from_task: %s\n", buf);

	// memcpy failed
	if (n != strlen(data) + 1 || strcmp(data, buf)) {
		ret = -1;
	}

	free_task(task);

	return ret;
}

TEST(Task,	copy_to_task,	0)
{
	char data[] = "ABCDEFG";
	char buf[64] = "XXXXXX";
	int ret = 0;
	int n;

	struct task *task = open_task(getpid());

	n = memcpy_to_task(task, (unsigned long)buf, data, strlen(data) + 1);
	ldebug("memcpy_to_task: %s\n", buf);

	// memcpy failed
	if (n != strlen(data) + 1 || strcmp(data, buf)) {
		ret = -1;
	}

	free_task(task);

	return ret;
}

TEST(Task,	mmap_malloc,	0)
{
	int ret = -1;
	int status = 0;

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			"sleep", "2", NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	} else if (pid > 0) {
		char data[] = "ABCDEFG";
		char buf[64] = "XXXXXX";
		int n;
		unsigned long addr;

		sleep(1);

		struct task *task = open_task(pid);

		// dump_task_vmas(task);

		ret = task_attach(pid);
		addr = task_malloc(task, 64);
		ldebug("task %lx, addr = %lx\n", task, addr);

		dump_task_vmas(task);

		n = memcpy_to_task(task, addr, data, strlen(data) + 1);
		n = memcpy_from_task(task, buf, addr, strlen(data) + 1);
		ldebug("memcpy_from_task: %s\n", buf);

		// memcpy failed
		if (n != strlen(data) + 1 || strcmp(data, buf)) {
			ret = -1;
		}

		ret = task_detach(pid);
		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
		free_task(task);
	} else {
		lerror("fork(2) error.\n");
	}

	return ret;
}

TEST(Task,	fstat,	0)
{
	int ret = 0;
	int status = 0;

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			"sleep", "2", NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	} else if (pid > 0) {

		sleep(1);

		int remote_fd, local_fd;
		struct stat stat = {};
		struct stat statbuf = {};
		struct task *task = open_task(pid);
		char *filename = "/usr/bin/ls";

		ret = task_attach(pid);
		remote_fd = task_open(task, filename, O_RDONLY, 0644);
		if (remote_fd <= 0) {
			lwarning("remote open failed.\n");
			return -1;
		}
		local_fd = open(filename, O_RDONLY, 0644);
		if (local_fd <= 0) {
			lwarning("open failed.\n");
			return -1;
		}

		fstat(local_fd, &stat);
		ret = task_fstat(task, remote_fd, &statbuf);

		if (stat.st_size != statbuf.st_size) {
			lerror("st_size not equal: remote(%d) vs local(%d)\n",
				statbuf.st_size, stat.st_size);
			ret = -1;
		}

		ldebug("stat.st_size = %d\n", statbuf.st_size);

		task_close(task, remote_fd);
		task_detach(pid);

		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
		free_task(task);
	} else {
		lerror("fork(2) error.\n");
	}

	ldebug("ret = %d\n", ret);

	return ret;
}

static int test_mmap_file(struct task *task, int prot)
{
	int ret = 0;
	unsigned long map_v;
	ssize_t map_len = 8192;
	int __unused map_fd;
	char filename[] = "todo.txt";

	map_fd = task_open(task, filename, O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (map_fd <= 0) {
		lwarning("remote open failed.\n");
		return -1;
	}
	ldebug("New open. %d\n", map_fd);
	ret = task_ftruncate(task, map_fd, map_len);
	if (ret != 0) {
		lwarning("remote ftruncate failed.\n");
		goto close_ret;
	}
	map_v = task_mmap(task,
				0UL, map_len,
				prot,
				MAP_PRIVATE, map_fd, 0);
	ldebug("New mmap. %lx\n", map_v);

	update_task_vmas(task);
	dump_task_vmas(task);

	ldebug("unmmap. %lx\n", map_v);
	task_munmap(task, map_v, map_len);

	unlink(filename);

close_ret:
	task_close(task, map_fd);

	return ret;
}

static int task_mmap_file(int prot)
{
	int ret = -1;
	int status = 0;

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			"sleep", "2", NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	} else if (pid > 0) {

		sleep(1);

		struct task *task = open_task(pid);

		dump_task_vmas(task);

		task_attach(pid);
		ret = test_mmap_file(task, prot);

		task_detach(pid);

		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
		free_task(task);
	} else {
		lerror("fork(2) error.\n");
	}

	return ret;
}
TEST(Task,	mmap_file_rw,	0)
{
	return task_mmap_file(PROT_READ | PROT_WRITE);
}
TEST(Task,	mmap_file_rwx,	0)
{
	return task_mmap_file(PROT_READ | PROT_WRITE | PROT_EXEC);
}

TEST(Task,	prctl_PR_SET_NAME,	0)
{
	int ret = -1;
	int status = 0;

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			"sleep", "2", NULL
		};
		ret = execvp(argv[0], argv);
		if (ret == -1) {
			exit(1);
		}
	} else if (pid > 0) {
		char data[] = "ABCDEFG";
		char buf[64] = "XXXXXX";
		int n;
		unsigned long addr;

		sleep(1);

		struct task *task = open_task(pid);

		// dump_task_vmas(task);

		ret = task_attach(pid);
		addr = task_malloc(task, 64);
		ldebug("task %lx, addr = %lx\n", task, addr);

		dump_task_vmas(task);

		n = memcpy_to_task(task, addr, data, strlen(data) + 1);

		// Set thread name
		// see:
		// $ ps -ef | grep sleep
		// $ top -Hp PID  ot top -Hp $(pidof sleep)
		//     PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
		//  150186 rongtao   20   0    5584    980    876 t   0.0   0.0   0:00.00 ABCDEFG
		ret = task_prctl(task, PR_SET_NAME, addr, 0, 0, 0);

		n = memcpy_from_task(task, buf, addr, strlen(data) + 1);
		ldebug("memcpy_from_task: %s\n", buf);

		// memcpy failed
		if (n != strlen(data) + 1 || strcmp(data, buf)) {
			ret = -1;
		}

		ret = task_detach(pid);
		waitpid(pid, &status, __WALL);
		if (status != 0) {
			ret = -EINVAL;
		}
		free_task(task);
	} else {
		lerror("fork(2) error.\n");
	}

	return ret;
}

