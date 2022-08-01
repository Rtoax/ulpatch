#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <elf/elf_api.h>
#include <patch/patch.h>

#include "test_api.h"

#if defined(__x86_64__)

static int ret_TTWU = 0;

#define TTWU_FTRACE_RETURN	1

static void my_direct_func(void)
{
	ldebug(">>>>> REPLACE mcount() <<<<<\n");
	ret_TTWU = TTWU_FTRACE_RETURN;
}

static int try_to_wake_up(void)
{
	ldebug("TTWU emulate.\n");
	return ret_TTWU;
}

TEST(Patch,	ftrace_direct,	TTWU_FTRACE_RETURN)
{
	int ret = 0;
	struct task *task = open_task(getpid());

	try_to_wake_up();

	memshow(try_to_wake_up, MCOUNT_INSN_SIZE * 2);

	unsigned long call_addr = (unsigned long)try_to_wake_up + MCOUNT_INSN_SIZE - 1;
	unsigned long ip = call_addr + 1;
	unsigned long addr = (unsigned long)my_direct_func;
	unsigned long __unused off = addr - call_addr - 5;

	ldebug("ip:%#0lx addr:%#0lx call:%#0lx\n", ip, addr, call_addr);

	// MUST use memcpy_to_task here, because ip has no write permission, but
	// pwrite(2) or ptrace(2) has.
	ret = memcpy_to_task(task, (unsigned long)ip, (void*)&off, 4);
	if (ret != 4) {
		lerror("failed to memcpy.\n");
	}

	memshow(try_to_wake_up, MCOUNT_INSN_SIZE * 2);

	// call again, my_direct_func will be called.
	ret = try_to_wake_up();

	free_task(task);

	return ret;
}
#endif // __x86_64__

