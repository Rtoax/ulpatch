// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2026 Rong Tao */
#pragma once
#include <sys/types.h>
#if defined(CONFIG_OPENSSL)
#include <openssl/md5.h>
#include <openssl/evp.h>
#endif

typedef enum {
	FILE_UNKNOWN = 0,
	FILE_ELF = 0x1 << 0,
	/* ELF LSB relocatable */
	FILE_ELF_RELO = FILE_ELF | (0x1 << 1),
} file_type;

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


int fsize(const char *filepath);
bool fexist(const char *filepath);
bool fregular(const char *filepath);
int fremove(const char *filepath);
int ftouch(const char *filepath, size_t size);
int fremove_recursive(const char *filepath);
file_type ftype(const char *filepath);
int fcopy(const char *srcpath, const char *dstpath);
char *fmktempfile(char *buf, int buf_len, char *seed);
char *fmktempname(char *buf, int buf_len, char *seed);
int fmemcpy(void *mem, int mem_len, const char *file);
struct mmap_struct *fmmap_rdonly(const char *filepath);
struct mmap_struct *fmmap_shmem_create(const char *filepath, size_t size);
int fmunmap(struct mmap_struct *mem);
int fprint_file(FILE *out, const char *file);
int fprint_fd(FILE *fp, int fd);
int dir_iter(const char *dirname, void (*callback)(const char *name, void *arg),
	     void *arg);

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
