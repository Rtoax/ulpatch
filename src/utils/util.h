// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <limits.h>

#include "utils/file.h"
#include "utils/list.h"
#include "utils/backtrace.h"
#include "utils/macros.h"
#include "utils/time.h"


struct nr_idx_bool {
	uint32_t nr;
	uint32_t idx;
	uint32_t is;
};

struct str_node {
	/* list: pre_load_files */
	struct list_head node;
	char *str; /* malloc, strdup */
};


void ulpatch_init(void);

int ulp_page_size(void);
int ulp_page_shift(void);

bool is_verbose(void);
int get_verbose(void);
void enable_verbose(int verbose);
void reset_verbose(void);
int str2verbose(const char *str);

bool is_dry_run(void);
void enable_dry_run(void);

/* Check some thing */
bool is_root(const char *prog);

int ulpatch_version_major(void);
int ulpatch_version_minor(void);
int ulpatch_version_patch(void);
const char *ulpatch_version(void);
const char *ulpatch_arch(void);
void ulpatch_info(const char *progname);

void daemonize(void);

int memshow(FILE *fp, const void *data, int data_len);
int memshowinlog(int level, const void *data, int data_len);
void print_string_hex(FILE *fp, const char *comment, unsigned char *str,
		      size_t len);
int print_bytes(FILE *fp, void *mem, size_t len);

/* Return TRUE if the start of STR matches PREFIX, FALSE otherwise.  */
int ulp_startswith(const char *str, const char *prefix);

/**
 * @src: string like a,b,c,d,e  MUST no whitespace
 * @list: list head of str_node
 *
 * return number of list nodes
 */
int parse_strstr(char *src, struct list_head *list);
void free_strstr_list(struct list_head *list);

unsigned long str2size(const char *str);
unsigned long str2addr(const char *str);
void *strbytes2mem(const char *bytes, size_t *nbytes, void *buf, size_t buf_len,
		   char seperator);
char *mem2strbytes(const void *mem, size_t mem_len, char *bytes_buf,
		   size_t buf_len, char seperator);

int fmembytes(FILE *fp, const void *data, int data_len);
char *strprintbuf(char *buf, size_t buf_size, const char *fmt, ...);

#define strstr_for_each_node_safe(iter, tmp, list)	\
	list_for_each_entry_safe(iter, tmp, list, node)
