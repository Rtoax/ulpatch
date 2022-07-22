#include <stdarg.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>


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

