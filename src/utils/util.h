// Copyright Copyright (c) 2022
#ifndef _UTIL_H
#define _UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 4096
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((unsigned long) &((TYPE*)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
	((type *)(((char *)(ptr)) - offsetof(type,member)))
#endif

#ifndef ROUND_DOWN
#define ROUND_DOWN(x, m) ((x) & ~((m) - 1))
#endif
#ifndef ROUND_UP
#define ROUND_UP(x, m) (((x) + (m) - 1) & ~((m) - 1))
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

/* Indirect stringification.  Doing two levels allows the parameter to be a
 * macro itself.  For example, compile with -DFOO=bar, __stringify(FOO)
 * converts to "bar".
 * see linux:include/linux/stringify.h
 */
#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)


struct list_head {
	struct list_head *next, *prev;
};

typedef enum {
	FILE_UNKNOWN,
	FILE_ELF,
} file_type;

// elftools arguments configuration
struct config {
	int log_level;
	enum {
		ROLE_SERVER, ROLE_CLIENT,
	} role;
	enum {
		MODE_SLEEP, MODE_CLI, MODE_GTK,
	} mode;
	bool daemon;
};

struct nr_idx_bool {
	uint32_t nr;
	uint32_t idx;
	uint32_t is;
};

struct str_node {
	// list: pre_load_files
	struct list_head node;
	char *str; // malloc, strdup
};

// Global configuration
extern struct config config;

const char *elftools_version(void);
const char *elftools_arch(void);

void daemonize(void);

int memshow(void *data, int data_len);
/* Return TRUE if the start of STR matches PREFIX, FALSE otherwise.  */
int startswith (const char *str, const char *prefix);

/**
 * @src: string like a,b,c,d,e  MUST no whitespace
 * @list: list head of str_node
 *
 * return number of list nodes
 */
int parse_strstr(char *src, struct list_head *list);
void free_strstr_list(struct list_head *list);

#define strstr_for_each_node_safe(iter, tmp, list)	\
	list_for_each_entry_safe(iter, tmp, list, node)


struct mmap_struct {
	char *filepath;
	int fd;
	int flags;
	int prot;
	void *mem;
	size_t size;
};

/* there are some file mmap apis
 */
int fsize(const char *filepath);
bool fexist(const char *filepath);
struct mmap_struct *fmmap_rdonly(const char *filepath);
int fmunmap(struct mmap_struct *mem);


#ifdef __cplusplus
}
#endif
#endif /* _UTIL_H */

