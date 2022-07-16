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
