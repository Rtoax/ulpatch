#include <stdarg.h>
#include <assert.h>
#include <libgen.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "list.h"

int memshow(void *data, int data_len)
{
	if (!data || data_len <= 0) return -EINVAL;
	int i;
	unsigned char *c = (unsigned char *)data;
	for (i = 0; i < data_len; i++) {
		printf("%02x ", c[i]);
	} printf("\n");

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

