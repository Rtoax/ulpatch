#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>

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
	struct task *task = open_task(1);

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
			"sleep", "0.1", NULL
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
		lerror("vfork(2) error.\n");
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

