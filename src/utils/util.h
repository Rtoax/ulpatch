// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022 Rong Tao */
#ifndef _UTIL_H
#define _UTIL_H

#include <errno.h>
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

#ifndef MAX
#define MAX(a, b) ((a > b) ? a : b)
#endif

#ifndef MIN
#define MIN(a, b) ((a > b) ? b : a)
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

#ifndef BIT
#define BIT(n)		(1UL << (n))
#endif

#if defined(KERNEL_HEADERS_CONST_H)
#include <linux/const.h>
#else
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

// see linux:include/linux/kernel.h
/* @a is a power of 2 value */
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))

// see linux:include/linux/sizes.h
#define SZ_1				0x00000001
#define SZ_2				0x00000002
#define SZ_4				0x00000004
#define SZ_8				0x00000008
#define SZ_16				0x00000010
#define SZ_32				0x00000020
#define SZ_64				0x00000040
#define SZ_128				0x00000080
#define SZ_256				0x00000100
#define SZ_512				0x00000200

#define SZ_1K				0x00000400
#define SZ_2K				0x00000800
#define SZ_4K				0x00001000
#define SZ_8K				0x00002000
#define SZ_16K				0x00004000
#define SZ_32K				0x00008000
#define SZ_64K				0x00010000
#define SZ_128K				0x00020000
#define SZ_256K				0x00040000
#define SZ_512K				0x00080000

#define SZ_1M				0x00100000
#define SZ_2M				0x00200000
#define SZ_4M				0x00400000
#define SZ_8M				0x00800000
#define SZ_16M				0x01000000
#define SZ_32M				0x02000000
#define SZ_64M				0x04000000
#define SZ_128M				0x08000000
#define SZ_256M				0x10000000
#define SZ_512M				0x20000000

#define SZ_1G				0x40000000
#define SZ_2G				0x80000000


/* all output need file store here, mkdir(2) it before running.
 */
#define ROOT_DIR	"/tmp/elftools"


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
	FILE_UNKNOWN = 0,
	FILE_ELF = 0x1 << 0,
	// ELF LSB relocatable
	FILE_ELF_RELO = FILE_ELF | (0x1 << 1),
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


void elftools_init(void);
const char *elftools_version(void);
const char *elftools_arch(void);

void daemonize(void);

int memshow(const void *data, int data_len);
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
	file_type ftype;
	int fd;
	int open_flags;
	int mmap_flags;
	int prot;
	void *mem;
	size_t size;
};

/* there are some file mmap apis
 */
int fsize(const char *filepath);
bool fexist(const char *filepath);
file_type ftype(const char *filepath);
int fcopy(const char *srcpath, const char *dstpath);
char* fmktempname(char *buf, int buf_len, char *seed);
int copy_chunked_from_file(void *mem, int mem_len, const char *file);

struct mmap_struct *fmmap_rdonly(const char *filepath);
struct mmap_struct *fmmap_shmem(const char *filepath);
int fmunmap(struct mmap_struct *mem);


#ifdef __cplusplus
}
#endif
#endif /* _UTIL_H */

