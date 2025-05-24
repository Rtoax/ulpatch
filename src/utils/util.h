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
#if defined(CONFIG_OPENSSL)
#include <openssl/md5.h>
#include <openssl/evp.h>
#endif

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 4096
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((unsigned long) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
	((type *)(((char *)(ptr)) - offsetof(type, member)))
#endif

#ifndef MAX
#define MAX(a, b) ((a > b) ? a : b)
#endif

#ifndef MIN
#define MIN(a, b) ((a > b) ? b : a)
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE (1UL << ulp_page_shift())
#endif

#ifndef PAGE_SHIFT
#define PAGE_SHIFT ulp_page_shift()
#endif

#define ELF_MIN_ALIGN	PAGE_SIZE

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#ifndef ROUND_DOWN
#define ROUND_DOWN(x, m) ((x) & ~((m) - 1))
#endif
#ifndef ROUND_UP
#define ROUND_UP(x, m) (((x) + (m) - 1) & ~((m) - 1))
#endif

#ifndef PAGE_DOWN
#define PAGE_DOWN(x) ROUND_DOWN(x, PAGE_SIZE)
#endif
#ifndef PAGE_UP
#define PAGE_UP(x) ROUND_UP(x, PAGE_SIZE)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#if defined(HAVE_KERNEL_HEADERS_CONST_H)
#include <linux/const.h>
#endif

#if !defined(KERNEL_HEADERS_CONST___ALIGN_KERNEL_H)
#if !defined(__ALIGN_KERNEL)
# define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#endif
#if !defined(__ALIGN_KERNEL_MASK)
# define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#endif

#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

/* see linux:include/linux/kernel.h */
/* @a is a power of 2 value */
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))

#ifndef ENOTSUPP
# define ENOTSUPP	524
#endif

/* see linux:include/linux/sizes.h */
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

#define KB (sizeof(uint8_t) * 1024UL)
#define MB (KB * 1024UL)
#define GB (MB * 1024UL)


/* all output need file store here, mkdir(2) it before running. */
#define ULP_PROC_ROOT_DIR	"/tmp/ulpatch"

#define MODE_0777 (S_IRUSR | S_IWUSR | S_IXUSR | \
		   S_IRGRP | S_IWGRP | S_IXGRP | \
		   S_IROTH | S_IWOTH | S_IXOTH)


/* Indirect stringification.  Doing two levels allows the parameter to be a
 * macro itself.  For example, compile with -DFOO=bar, __stringify(FOO)
 * converts to "bar".
 * see linux:include/linux/stringify.h
 */
#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)


#if defined(CONFIG_LIBUNWIND) && defined(CONFIG_LIBUNWIND)
int do_backtrace(FILE *fp);
const char *libunwind_version(void);
#else
# define do_backtrace(fp) ({-1;})
# define libunwind_version()	"Not support libunwind"
#endif


struct list_head {
	struct list_head *next, *prev;
};

typedef enum {
	FILE_UNKNOWN = 0,
	FILE_ELF = 0x1 << 0,
	/* ELF LSB relocatable */
	FILE_ELF_RELO = FILE_ELF | (0x1 << 1),
} file_type;

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

/* File and directory operations */
int fsize(const char *filepath);
bool fexist(const char *filepath);
bool fregular(const char *filepath);
int ftouch(const char *filepath, size_t size);
int fremove(const char *filepath);
int fremove_recursive(const char *filepath);
file_type ftype(const char *filepath);
int fcopy(const char *srcpath, const char *dstpath);
char *fmktempfile(char *buf, int buf_len, char *seed);
char *fmktempname(char *buf, int buf_len, char *seed);
int fmemcpy(void *mem, int mem_len, const char *file);
int fprint_file(FILE *fp, const char *file);
int fprint_fd(FILE *fp, int fd);
int dir_iter(const char *dirname, void (*callback)(const char *name));

#ifndef MD5_DIGEST_LENGTH
/* see /usr/include/openssl/md5.h */
#define MD5_DIGEST_LENGTH 16
#endif
#ifdef EVP_MAX_MD_SIZE
/* see /usr/include/openssl/evp.h */
#define EVP_MAX_MD_SIZE 64
#endif
#if defined(CONFIG_OPENSSL)
int fmd5sum(const char *filename, unsigned char *md5_result);
#else
#define fmd5sum(filename, md5_result) ({-ENOTSUPP;})
#endif

struct mmap_struct *fmmap_rdonly(const char *filepath);
struct mmap_struct *fmmap_shmem_create(const char *filepath, size_t size);
int fmunmap(struct mmap_struct *mem);


/* callback chain */
struct callback_chain {
	struct list_head head;
};

int insert_callback(struct callback_chain *chain,
		int (*cb)(void *arg), void *cb_arg);
void callback_launch_chain(struct callback_chain *chain);
int destroy_callback_chain(struct callback_chain *chain);

unsigned long secs(void);
unsigned long usecs(void);
