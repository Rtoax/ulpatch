// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <utils/task.h>
#include <elf/elf_api.h>
#include <patch/patch.h>

#include "../test_api.h"


struct patch_test_arg {
	void (*custom_mcount)(void);
	enum {
		REPLACE_MCOUNT,
		REPLACE_NOP,
	} replace;
};

extern void mcount(void);
extern void _mcount(void);

static int ret_TTWU = 0;

#define TTWU_FTRACE_RETURN	1

/* when mcount() be called at the first time, mcount's address will be parse
 * so that, if you don't access mcount, sym.st_value will be '0'
 */
#if defined(__x86_64__)
__unused char const *mcount_str = "mcount";
__unused const unsigned long mcount_addr = (unsigned long)mcount;
#elif defined(__aarch64__)
__unused char const *mcount_str = "_mcount";
__unused const unsigned long mcount_addr = (unsigned long)_mcount;
#endif

static void my_direct_func(void)
{
	linfo(">>>>> REPLACE mcount() <<<<<\n");
	ret_TTWU = TTWU_FTRACE_RETURN;
}

/* see macro UPATCH_TEST code branch */
 __opt_O0 int try_to_wake_up(struct task *task, int mode, int wake_flags)
{
	linfo("TTWU emulate.\n");
	int ret = ret_TTWU;
	ret_TTWU = 0;
	return ret;
}

static int direct_patch_test(struct patch_test_arg *arg)
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

	try_to_wake_up(task, 0, 0);

#if defined(__x86_64__)

	unsigned long ip = (unsigned long)try_to_wake_up +
		x86_64_func_callq_offset(try_to_wake_up);
	unsigned long addr = (unsigned long)arg->custom_mcount;

	union text_poke_insn insn;
	const char *new = NULL;

	switch (arg->replace) {
	case REPLACE_MCOUNT:
		new = ftrace_call_replace(&insn, ip, addr);
		break;
	case REPLACE_NOP:
		new = ftrace_nop_replace();
		break;
	}

	linfo("addr:%#0lx call:%#0lx\n", addr, ip);
	memshow((void*)ip, MCOUNT_INSN_SIZE);

	ret = memcpy_to_task(task, ip, (void*)new, MCOUNT_INSN_SIZE);
	if (ret != MCOUNT_INSN_SIZE) {
		lerror("failed to memcpy.\n");
	}

	memshow((void*)ip, MCOUNT_INSN_SIZE);

#elif defined(__aarch64__)

	// TODO: how to get bl <_mcount> address (24)
	unsigned long pc =
		(unsigned long)try_to_wake_up + aarch64_func_bl_offset(try_to_wake_up);
	uint32_t new = aarch64_insn_gen_branch_imm(pc,
						(unsigned long)arg->custom_mcount,
						AARCH64_INSN_BRANCH_LINK);

	linfo("pc:%#0lx new addr:%#0lx, mcount_offset %d\n",
		pc, new, aarch64_func_bl_offset(try_to_wake_up));

	memshow((void*)pc, MCOUNT_INSN_SIZE);

	/* application the patch */
	ftrace_modify_code(task, pc, 0, new, false);

	memshow((void*)pc, MCOUNT_INSN_SIZE);

#endif

	// call again, custom_mcount() will be called.
	// see macro UPATCH_TEST code branch
	ret = try_to_wake_up(task, 1, 2);

	free_task(task);

	return ret;
}

TEST(Patch,	ftrace_direct,	TTWU_FTRACE_RETURN)
{
	struct patch_test_arg arg = {
		.custom_mcount = my_direct_func,
		.replace = REPLACE_MCOUNT,
	};

	return direct_patch_test(&arg);
}

TEST(Patch,	ftrace_object,	0)
{
	struct patch_test_arg arg = {
		.custom_mcount = _ftrace_mcount,
		.replace = REPLACE_MCOUNT,
	};

	return direct_patch_test(&arg);
}

#if defined(__x86_64__)
TEST(Patch,	ftrace_nop,	0)
{
	struct patch_test_arg arg = {
		.custom_mcount = NULL,
		.replace = REPLACE_NOP,
	};

	return direct_patch_test(&arg);
}
#endif

