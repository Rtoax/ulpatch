// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#include <stdarg.h>
#include <assert.h>
#include <libgen.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include "list.h"

int memshow(const void *data, int data_len)
{
	if (!data || data_len <= 0) return -EINVAL;

	int i, iline;
	const int align = 16;

	for (iline = 0; iline * align < data_len; iline++) {

		unsigned char *line = (unsigned char *)data + iline * align;

		printf("%08x  ", iline * align);

		for (i = 0; i < align; i++) {
			char *e = " ";
			int len = iline * align + i;

			if (i == align / 2 - 1)
				e = "  ";

			if (len >= data_len) {
				printf("%2s%s", "", e);
			} else {
				printf("%02x%s", line[i], e);
			}
		}

		printf("  |");

		for (i = 0; i < align; i++) {
			char e = '.';
			int len = iline * align + i;

			if (isprint(line[i]))
				e = line[i];

			if (len >= data_len) {
				printf(" ");
			} else {
				printf("%c", e);
			}
		}

		printf("|\n");
	}

	return 0;
}

/* Return TRUE if the start of STR matches PREFIX, FALSE otherwise.  */
int startswith (const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen (prefix)) == 0;
}

static void __add_to_str_list(const char *name, struct list_head *list)
{
	struct str_node *str = malloc(sizeof(struct str_node));
	assert(str && "malloc failed");

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
	int n = 0;

	assert(src && "NULL pointer");

	char *newstr = strdup(src);
	char *p = newstr;

	// a,b,c,,d,e,,,
	// >>
	// a b c d e
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

			if (name[0] != '\0') {
				__add_to_str_list(name, list);
				n++;
			}
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

