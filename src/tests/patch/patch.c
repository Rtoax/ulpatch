// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <errno.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <task/task.h>
#include <utils/disasm.h>
#include <elf/elf-api.h>
#include <patch/asm.h>
#include <patch/patch.h>

#include <tests/test-api.h>

TEST_STUB(patch_patch);

static int ret_TTWU = 0;

__opt_O0 int try_to_wake_up(struct task_struct *task, int mode, int wake_flags)
{
	ulp_info("TTWU emulate.\n");
	int ret = ret_TTWU;
	ret_TTWU = 0;
	return ret;
}

__opt_O0 int ulpatch_try_to_wake_up(struct task_struct *task, int mode,
				    int wake_flags)
{
#define ULPATCH_TTWU_RET	0xdead1234
	ulp_info("TTWU emulate, patched.\n");
	return ULPATCH_TTWU_RET;
}

TEST(Patch, direct_jmp, 0)
{
	int ret = 0;
	int flags = FTO_VMA_ELF_FILE | FTO_RDWR;
	struct task_struct *task = open_task(getpid(), flags);

	unsigned long ip_pc = (unsigned long)try_to_wake_up;
	unsigned long addr = (unsigned long)ulpatch_try_to_wake_up;

	/**
	 * Skip symbols whose symbol address length is longer than 4 bytes.
	 * After all, this method is designed to test 4-byte addresses.
	 */
	if ((addr & 0xFFFFFFFFUL) != addr) {
		ulp_warning("Not support address overflow 4 bytes length.\n");
		return 0;
	}

#if defined(__x86_64__)
	union text_poke_insn insn;
	const char *new = NULL;

	new = ulpatch_jmpq_replace(&insn, ip_pc, addr);

	ulp_info("addr:%#0lx jmp:%#0lx\n", addr, ip_pc);

	try_to_wake_up(task, 1, 1);

	ret = memcpy_to_task(task, ip_pc, (void*)new, MCOUNT_INSN_SIZE);
	if (ret == -1 || ret != MCOUNT_INSN_SIZE) {
		ulp_error("failed to memcpy.\n");
	}
#elif defined(__aarch64__)
	uint32_t new = aarch64_insn_gen_branch_imm(ip_pc, addr,
					    AARCH64_INSN_BRANCH_NOLINK);

	ulp_info("pc:%#0lx new addr:%#0x\n", ip_pc, new);

	try_to_wake_up(task, 1, 1);
	/* application the patch */
	ftrace_modify_code(task, ip_pc, 0, new, false);
#endif

	/* This will called patched function ulpatch_try_to_wake_up() */
	ret = try_to_wake_up(task, 1, 1);
	if (ret != ULPATCH_TTWU_RET)
		ret = -1;
	else
		ret = 0;

	close_task(task);
	return ret;
}

TEST(Patch, direct_jmp_table, 0)
{
	int ret = 0, test_ret = 0;
	int flags = FTO_VMA_ELF_FILE | FTO_RDWR;
	struct task_struct *task = open_task(getpid(), flags);

	unsigned long ip_pc = (unsigned long)try_to_wake_up;
	unsigned long addr = (unsigned long)ulpatch_try_to_wake_up;

	const char *new = NULL;
	char orig_code[sizeof(struct jmp_table_entry)];
	struct jmp_table_entry jmp_entry;

	jmp_entry.jmp = arch_jmp_table_jmp();
	jmp_entry.addr = addr;
	new = (void *)&jmp_entry;

	ulp_info("addr:%#0lx jmp:%#0lx\n", addr, ip_pc);

	try_to_wake_up(task, 1, 1);
	fdisasm_arch(stdout, NULL, ip_pc, (void *)ip_pc, sizeof(jmp_entry));

	/* Store original code */
	ret = memcpy_from_task(task, orig_code, ip_pc, sizeof(jmp_entry));
	if (ret == -1 || ret < sizeof(jmp_entry)) {
		ulp_error("failed to memcpy, ret = %d.\n", ret);
	}

	ret = memcpy_to_task(task, ip_pc, (void *)new, sizeof(jmp_entry));
	if (ret == -1 || ret < sizeof(jmp_entry)) {
		ulp_error("failed to memcpy, ret = %d.\n", ret);
	}

	fdisasm_arch(stdout, NULL, ip_pc, (void *)ip_pc, sizeof(jmp_entry));

	/* This will called patched function ulpatch_try_to_wake_up() */
	ret = try_to_wake_up(task, 1, 1);
	if (ret != ULPATCH_TTWU_RET)
		test_ret = -1;
	else
		test_ret = 0;

	/* Restore original code */
	ret = memcpy_to_task(task, ip_pc, orig_code, sizeof(jmp_entry));
	if (ret == -1 || ret < sizeof(jmp_entry)) {
		ulp_error("failed to memcpy, ret = %d.\n", ret);
	}

	fdisasm_arch(stdout, NULL, ip_pc, (void *)ip_pc, sizeof(jmp_entry));

	close_task(task);
	return test_ret;
}

static int static_asm_putchar(int ret)
{
	char msg[] = {"Hello-\n"};
	int len = 7;
	ASM_WRITE(1, msg, len);
	ASM_WRITE_HELLO();
	return ret;
}

static int static_asm_putchar_end(int ret)
{
	/* Make sure here could store a jmp_table_entry, ensure not overflow */
	char __unused buf[sizeof(struct jmp_table_entry)];
	return 0;
}

typedef int (*putchar_fn)(int c);

TEST(Patch, direct_jmp_far, 0)
{
	int test_ret = 0, ret, expect_ret;
	int flags = FTO_VMA_ELF_FILE | FTO_RDWR;
	struct task_struct *task = open_task(getpid(), flags);
	unsigned long addr, map_len, ip_pc;
	void *mem;
	char orig_code[sizeof(struct jmp_table_entry)];
	struct jmp_table_entry jmp_entry;
	const char *new = NULL;
	putchar_fn fn = NULL;

	map_len = static_asm_putchar_end - static_asm_putchar;

	addr = find_vma_span_area(task, map_len, MIN_ULP_START_VMA_ADDR);
	if ((addr & 0x00000000FFFFFFFFUL) != addr) {
		ulp_warning("Not found 4 bytes length address span area in memory space.\n"\
			"please: cat /proc/%d/maps\n", task->pid);
	}

	mem = mmap((void *)addr, map_len, PROT_READ | PROT_WRITE | PROT_EXEC,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		ulp_error("remote mmap failed.\n");
		test_ret = -EFAULT;
		goto close_ret;
	}

	memcpy(mem, static_asm_putchar, map_len);
	mprotect(mem, map_len, PROT_READ | PROT_EXEC);

	ulp_info("mmap mem %p, addr %lx\n", mem, addr);

	fprint_file(stdout, "/proc/self/maps");

	fdisasm_arch(stdout, NULL, addr, mem, map_len);

	jmp_entry.jmp = arch_jmp_table_jmp();
	jmp_entry.addr = (unsigned long)mem;
	new = (void *)&jmp_entry;

	memcpy(orig_code, static_asm_putchar_end, sizeof(jmp_entry));

	ip_pc = (unsigned long)static_asm_putchar_end;

	ret = memcpy_to_task(task, ip_pc, (void *)new, sizeof(jmp_entry));
	if (ret == -1 || ret < sizeof(jmp_entry)) {
		ulp_error("failed to memcpy, ret = %d.\n", ret);
	}
	fdisasm_arch(stdout, NULL, ip_pc, (void *)ip_pc, sizeof(jmp_entry));

	fn = (putchar_fn)mem;

	expect_ret = 0xdead;

	ret = fn(expect_ret);
	if (ret != expect_ret) {
		ulp_error("Copy mem failed. ret = %x\n", ret);
		test_ret = -1;
	}

	ret = static_asm_putchar_end(expect_ret);
	if (ret != expect_ret) {
		ulp_error("Patch failed. ret = %x\n", ret);
		test_ret = -1;
	}

	ret = memcpy_to_task(task, ip_pc, orig_code, sizeof(jmp_entry));
	if (ret == -1 || ret < sizeof(jmp_entry)) {
		ulp_error("failed to memcpy, ret = %d.\n", ret);
	}
	fdisasm_arch(stdout, NULL, ip_pc, (void *)ip_pc, sizeof(jmp_entry));

close_ret:
	munmap(mem, map_len);
	close_task(task);
	return test_ret;
}
