// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <limits.h>
#include <stdlib.h>
#include <elf.h>
#include <dirent.h>

#include <elf/elf-api.h>

#include <utils/log.h>
#include <task/task.h>
#include <task/patch.h>


int alloc_ulp(struct vm_area_struct *vma)
{
	int ret;
	void *mem;
	struct vma_ulp *ulp;
	size_t ulp_size = vma->vm_end - vma->vm_start;
	struct task_struct *task = vma->task;

	ulp = malloc(sizeof(struct vma_ulp));
	if (!ulp) {
		ulp_error("malloc failed.\n");
		return -ENOMEM;
	}

	mem = malloc(ulp_size);
	if (!mem) {
		ulp_error("malloc failed.\n");
		return -ENOMEM;
	}

	vma->ulp = ulp;
	ulp->elf_mem = mem;
	ulp->vma = vma;
	ulp->str_build_id = NULL;

	/* Copy VMA from target task memory space */
	ret = memcpy_from_task(task, ulp->elf_mem, vma->vm_start, ulp_size);
	if (ret == -1 || ret < ulp_size) {
		ulp_error("Failed read %lx:%s\n", vma->vm_start, vma->name_);
		free_ulp(vma);
		errno = EAGAIN;
		return -EAGAIN;
	}

	list_add(&ulp->node, &task->ulp_list);
	return 0;
}

void free_ulp(struct vm_area_struct *vma)
{
	struct vma_ulp *ulp = vma->ulp;

	if (!ulp) {
		errno = EINVAL;
		return;
	}

	ulp_debug("Remove %s from ulpatch list.\n", vma->name_);

	list_del(&ulp->node);
	if (ulp->str_build_id)
		free(ulp->str_build_id);

	free(ulp->elf_mem);
	free(ulp);
	vma->ulp = NULL;
}

int vma_load_ulp(struct vm_area_struct *vma)
{
	int ret;
	GElf_Ehdr ehdr = {};
	struct task_struct *task = vma->task;
	struct load_info info = {
		.target_task = task,
	};

	ulp_debug("Load ulpatch vma %s.\n", vma->name_);

	ret = memcpy_from_task(task, &ehdr, vma->vm_start, sizeof(ehdr));
	if (ret == -1 || ret < sizeof(ehdr)) {
		ulp_error("Failed read from %lx:%s\n", vma->vm_start,
			  vma->name_);
		errno = EAGAIN;
		return -EAGAIN;
	}

	if (!ehdr_magic_ok(&ehdr)) {
		ulp_error("VMA %s(%lx) is ULPATCH, but it's not ELF.",
			  vma->name_, vma->vm_start);
		errno = ENOENT;
		return -ENOENT;
	}

	vma->is_elf = true;
	alloc_ulp(vma);

	load_ulp_info_from_vma(vma, &info);

	if (task->max_ulp_id < info.ulp_info->ulp_id)
		task->max_ulp_id = info.ulp_info->ulp_id;

	return 0;
}
