// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once

#include <patch/patch.h>

#include <utils/util.h>
#include <utils/rbtree.h>
#include <utils/list.h>

struct vm_area_struct;

struct vma_ulp {
	struct ulpatch_strtab strtab;
	struct ulpatch_author author;
	struct ulpatch_license license;
	struct ulpatch_info info;

	/* This is ELF */
	void *elf_mem;

#define MIN_ULP_START_VMA_ADDR	0x400000U
#define MAX_ULP_START_VMA_ADDR	0xFFFFFFFFUL
	/* Belongs to */
	struct vm_area_struct *vma;

	char *str_build_id;

	/* struct task_struct.ulp_list */
	struct list_head node;
};

int alloc_ulp(struct vm_area_struct *vma);
int vma_load_ulp(struct vm_area_struct *vma);
void free_ulp(struct vm_area_struct *vma);
