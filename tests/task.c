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
