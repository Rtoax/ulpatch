#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <elf/elf_api.h>
#include <patch/patch.h>

#include "test_api.h"


static int ret_TTWU = 0;

#define TTWU_FTRACE_RETURN	1

static void my_direct_func(void)
{
	ldebug(">>>>> REPLACE mcount() <<<<<\n");
	ret_TTWU = TTWU_FTRACE_RETURN;
}

static __opt_O0 int try_to_wake_up(void)
{
	ldebug("TTWU emulate.\n");
	return ret_TTWU;
}

TEST(Patch,	ftrace_direct,	TTWU_FTRACE_RETURN)
{
	int ret = 0;
	struct task *task = open_task(getpid());

	try_to_wake_up();

#if defined(__x86_64__)

	unsigned long call_addr = (unsigned long)try_to_wake_up + 4;
	unsigned long ip = call_addr + 1;
	unsigned long addr = (unsigned long)my_direct_func;
	unsigned long __unused off = addr - call_addr - MCOUNT_INSN_SIZE;

	ldebug("ip:%#0lx addr:%#0lx call:%#0lx\n", ip, addr, call_addr);
	memshow((void*)call_addr, MCOUNT_INSN_SIZE);

	// MUST use memcpy_to_task here, because ip has no write permission, but
	// pwrite(2) or ptrace(2) has.
	ret = memcpy_to_task(task, (unsigned long)ip, (void*)&off, MCOUNT_INSN_SIZE - 1);
	if (ret != 4) {
		lerror("failed to memcpy.\n");
	}

	memshow((void*)call_addr, MCOUNT_INSN_SIZE);

#elif defined(__aarch64__)

	// TODO: aarch64 ftrace
	return TTWU_FTRACE_RETURN;

	unsigned long bl_addr = (unsigned long)try_to_wake_up + 24;
	unsigned long addr = (unsigned long)my_direct_func;
	long off = (long)(addr - bl_addr);
	long _mcount_insn = 0U;

	_mcount_insn |= bl_addr & 0xfc000000U;
	_mcount_insn |= (off >> 2) & 0x03ffffffU;

	ldebug("addr:%#0lx bl:%#0lx new:%#0lx\n", addr, bl_addr, _mcount_insn);

	memshow((void*)bl_addr, MCOUNT_INSN_SIZE);

	ret = memcpy_to_task(task, (unsigned long)bl_addr, (void*)&_mcount_insn, MCOUNT_INSN_SIZE);
	if (ret != 4) {
		lerror("failed to memcpy.\n");
	}
	memshow((void*)bl_addr, MCOUNT_INSN_SIZE);

#endif

	// call again, my_direct_func will be called.
	ret = try_to_wake_up();

	free_task(task);

	return ret;
}

