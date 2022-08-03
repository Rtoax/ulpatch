#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <elf/elf_api.h>
#include <patch/patch.h>

#include "../test_api.h"


extern void mcount(void);
extern void _mcount(void);

static int ret_TTWU = 0;

#define TTWU_FTRACE_RETURN	1

/* when mcount() be called at the first time, mcount's address will be parse
 * so that, if you don't access mcount, sym.st_value will be '0'
 */
#if defined(__x86_64__)
char const *mcount_str = "mcount";
const unsigned long mcount_addr = (unsigned long)mcount;
#elif defined(__aarch64__)
char const *mcount_str = "_mcount";
const unsigned long mcount_addr = (unsigned long)_mcount;
#endif

static void my_direct_func(void)
{
	linfo(">>>>> REPLACE mcount() <<<<<\n");
	ret_TTWU = TTWU_FTRACE_RETURN;
}

static __opt_O0 int try_to_wake_up(void)
{
	linfo("TTWU emulate.\n");
	return ret_TTWU;
}

TEST(Patch,	ftrace_direct,	TTWU_FTRACE_RETURN)
{
	int ret = 0;
	struct task *task = open_task(getpid(), FTO_SELF | FTO_LIBC);

	struct symbol *rel_s = NULL;
	struct symbol *libc_s = NULL;


	/* Try to find mcount symbol in target task address space, you need to
	 * access mcount before find_symbol("mcount"), otherwise, st_value will be
	 * zero.
	 *
	 * AArch64: bl <_mcount> is 0x94000000 before relocation
	 */
	rel_s = find_symbol(task->exe_elf, mcount_str);
	if (!rel_s) {
		lerror("Not found mcount symbol in %s\n", task->exe);
		return -1;
	}

	/* Try to find mcount in libc.so, some time, libc.so's symbols is very
	 * useful when you try to patch a running process or ftrace it. so, this
	 * is a test.
	 */
	libc_s = find_symbol(task->libc_elf, mcount_str);
	if (!libc_s) {
		lerror("Not found mcount symbol\n", task->libc_elf->filepath);
		return -1;
	}

	dump_task(task);
	linfo("SELF: _mcount: st_value: %lx %lx\n",
		rel_s->sym.st_value, mcount_addr);
	linfo("LIBC: _mcount: st_value: %lx %lx\n",
		libc_s->sym.st_value, mcount_addr);

	try_to_wake_up();

#if defined(__x86_64__)

	unsigned long call_addr = (unsigned long)try_to_wake_up + 4;
	unsigned long ip = call_addr + 1;
	unsigned long addr = (unsigned long)my_direct_func;
	unsigned long __unused off = addr - call_addr - MCOUNT_INSN_SIZE;

	linfo("ip:%#0lx addr:%#0lx call:%#0lx\n", ip, addr, call_addr);
	memshow((void*)call_addr, MCOUNT_INSN_SIZE);

	// MUST use memcpy_to_task here, because ip has no write permission, but
	// pwrite(2) or ptrace(2) has.
	ret = memcpy_to_task(task, (unsigned long)ip, (void*)&off, MCOUNT_INSN_SIZE - 1);
	if (ret != 4) {
		lerror("failed to memcpy.\n");
	}

	memshow((void*)call_addr, MCOUNT_INSN_SIZE);

#elif defined(__aarch64__)

	// TODO: how to get bl <_mcount> address (24)
	unsigned long bl_addr = (unsigned long)try_to_wake_up + 24;
	unsigned long addr = (unsigned long)my_direct_func;

	uint32_t bl_insn = (*(uint32_t *)bl_addr) & 0xfc000000U;
	uint32_t bl_off = (addr - bl_addr);

	// TODO: how to calculate offset of "bl"
	bl_off >>= 2;
	bl_off &= 0x03ffffffU;

	uint32_t _mcount_insn = bl_insn | bl_off;

	linfo("dst addr:%#0lx, old addr:%#0lx, bl addr:%#0lx\n",
		addr, (unsigned long)_mcount, bl_addr);
	linfo("old insn:%#0lx, new insn:%#0lx\n", *(int32_t*)bl_addr, _mcount_insn);

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

