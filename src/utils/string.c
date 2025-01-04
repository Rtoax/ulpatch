// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdarg.h>
#include <libgen.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include <utils/list.h>
#include <utils/log.h>

/**
 * @fp - if NULL, return directly
 */
int memshow(FILE *fp, const void *data, int data_len)
{
	if (!data || data_len <= 0) return -EINVAL;

	int i, iline, len = 0;
	const int align = 16;

	if (!fp)
		return 0;

	for (iline = 0; iline * align < data_len; iline++) {

		unsigned char *line = (unsigned char *)data + iline * align;

		len += fprintf(fp, "%08x  ", iline * align);

		for (i = 0; i < align; i++) {
			char *e = " ";
			int len = iline * align + i;

			if (i == align / 2 - 1)
				e = "  ";

			if (len >= data_len) {
				len += fprintf(fp, "%2s%s", "", e);
			} else {
				len += fprintf(fp, "%02x%s", line[i], e);
			}
		}

		len += fprintf(fp, "  |");

		for (i = 0; i < align; i++) {
			char e = '.';
			int len = iline * align + i;

			if (isprint(line[i]))
				e = line[i];

			if (len >= data_len) {
				len += fprintf(fp, " ");
			} else {
				len += fprintf(fp, "%c", e);
			}
		}

		len += fprintf(fp, "|\n");
	}

	return len;
}

void print_string_hex(FILE *fp, const char *comment, unsigned char *str,
		      size_t len)
{
	unsigned char *c;
	if (comment)
		fprintf(fp, "%s", comment);
	for (c = str; c < str + len; c++)
		fprintf(fp, "0x%02x ", *c & 0xff);
	fprintf(fp, "\n");
}

int print_bytes(FILE *fp, void *mem, size_t len)
{
	int ret = 0;
	unsigned char *c, *str = mem;
	for (c = str; c < str + len; c++)
		ret += fprintf(fp, "%02x ", *c & 0xff);
	return ret;
}

int fmembytes(FILE *fp, const void *data, int data_len)
{
	int i;
	const uint8_t *b;

	if (!fp)
		fp = stdout;

	for (i = 0, b = data; i < data_len; i++, b++)
		fprintf(fp, "%02x%s", *b, i < (data_len - 1) ? " " : "");
	fprintf(fp, "\n");
	return 0;
}

/* Return TRUE if the start of STR matches PREFIX, FALSE otherwise.  */
int ulp_startswith(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

static void __add_to_str_list(const char *name, struct list_head *list)
{
	struct str_node *str = malloc(sizeof(struct str_node));
	if (!str) {
		ulp_error("Malloc str_node failed.\n");
		return;
	}

	str->str = strdup(name);
	list_add(&str->node, list);
}

static void __free_str(struct str_node *str)
{
	free(str->str);
	free(str);
}

/**
 * @src: string like a,b,c,d,e  MUST no whitespace
 * @list: list head of str_node
 *
 * return number of list nodes
 */
int parse_strstr(char *src, struct list_head *list)
{
	char *newstr = strdup(src);
	char *p = newstr;

	/**
	 * a,b,c,,d,e,,,
	 * >>
	 * a b c d e
	 */
	while (*p) {
		char *name = p;

		while (p && *p && *p != ',') {
			p++;
		}

		if (*p == ',' || *p == '\0') {
			if (*p == ',') {
				p[0] = '\0';
				p++;
			}

			if (name[0] != '\0')
				__add_to_str_list(name, list);
		} else break;
	}
	free(newstr);
	return 0;
}

void free_strstr_list(struct list_head *list)
{
	struct str_node *str = NULL, *tmp;

	strstr_for_each_node_safe(str, tmp, list) {
		__free_str(str);
	}
}

unsigned long str2size(const char *str)
{
	unsigned long size = 0;

	if (!str) {
		errno = EINVAL;
		return 0;
	}

	if (str[0] == '0' && str[1] == 'x')
		size = strtoull(str, NULL, 16);
	else
		size = strtoull(str, NULL, 10);

	if (strstr(str, "GB"))
		size *= GB;
	else if (strstr(str, "MB"))
		size *= MB;
	else if (strstr(str, "KB"))
		size *= KB;

	return size;
}

unsigned long str2addr(const char *str)
{
	unsigned long addr = 0;

	if (!str) {
		errno = EINVAL;
		return 0;
	}

	/* start with '0x' */
	if (str[0] == '0' && str[1] == 'x')
		addr = strtoull(str, NULL, 16);
	/* start with '0[0-9]' */
	else if (str[0] == '0' && (str[1] >= '0' && str[1] <= '9'))
		addr = strtoull(str, NULL, 8);
	else
		addr = strtoull(str, NULL, 10);

	return addr;
}
