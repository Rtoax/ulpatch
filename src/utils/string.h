// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once
#include "utils/list.h"

struct str_node {
	/* list: pre_load_files */
	struct list_head node;
	char *str; /* malloc, strdup */
};


#define strstr_for_each_node_safe(iter, tmp, list)	\
	list_for_each_entry_safe(iter, tmp, list, node)

int memshow(FILE *fp, const void *data, int data_len);
void print_string_hex(FILE *fp, const char *comment, unsigned char *str,
		      size_t len);
int print_bytes(FILE *fp, void *mem, size_t len);
int fmembytes(FILE *fp, const void *data, int data_len);
void *strbytes2mem(const char *bytes, size_t *nbytes, void *buf, size_t buf_len,
		   char seperator);
char *mem2strbytes(const void *mem, size_t mem_len, char *bytes_buf,
		   size_t buf_len, char seperator);
int ulp_startswith(const char *str, const char *prefix);
int parse_strstr(char *src, struct list_head *list);
void free_strstr_list(struct list_head *list);
unsigned long str2size(const char *str);
unsigned long str2addr(const char *str);
char *strprintbuf(char *buf, size_t buf_size, const char *fmt, ...);
