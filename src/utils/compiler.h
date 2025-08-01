// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#pragma once

#define compiler_barrier()	asm volatile("" :::"memory")

#if defined(__i386__) || defined(__x86_64__)
# define cpu_relax()		asm volatile("rep; nop" ::: "memory")
# define full_memory_barrier()	asm volatile("mfence" ::: "memory")
# define read_memory_barrier()  asm volatile("lfence" ::: "memory")
# define write_memory_barrier()	asm volatile("sfence" ::: "memory")
#endif

#if defined(__aarch64__)
# define cpu_relax()		asm volatile("yield" ::: "memory")
# define full_memory_barrier()	asm volatile("dmb ish" ::: "memory")
# define read_memory_barrier()  asm volatile("dmb ishld" ::: "memory")
# define write_memory_barrier()	asm volatile("dmb ishst" ::: "memory")
#endif

#if defined(__arm__)
# define cpu_relax()		compiler_barrier()
# if __ARM_ARCH == 7
#  define full_memory_barrier()  asm volatile("dmb ish" ::: "memory")
#  define read_memory_barrier()  asm volatile("dmb ish" ::: "memory")
#  define write_memory_barrier() asm volatile("dmb ishst" ::: "memory")
# else
#  define full_memory_barrier()  asm volatile ("mcr p15, 0, %0, c7, c10, 5" :: "r" (0) : "memory")
#  define read_memory_barrier()  full_memory_barrier()
#  define write_memory_barrier() full_memory_barrier()
# endif
#endif

/* ignore 'restrict' keyword if not supported (before C99) */
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
# define restrict
#endif

#define __weak __attribute__((weak))
#define __visible_default __attribute__((visibility("default")))
#define __hidden __attribute__((visibility("hidden")))
#define __alias(func) __attribute__((alias(#func)))
#define __maybe_unused __attribute__((unused))
#define __used __attribute__((used))
#define __unused __attribute__((unused))
#define __noreturn __attribute__((noreturn))
#define __align(n) __attribute__((aligned(n)))
#define __packed __attribute__((packed))
#define __printf(x, y) __attribute__((format(printf, x, y)))

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* Forced inlining */
#ifndef force_inline
#define force_inline __attribute__((__always_inline__))
#endif

#define __deprecated __attribute__((deprecated))

/* value: 101 ~ 200, 101 first */
#define __ctor(value) __attribute__((constructor(value)))

#define __section(sec) __attribute__((section(sec)))

/* Or use pragma:
 * #pragma GCC optimize("O0") */
#if defined(__clang__)
# define __opt_O0 __attribute__((optnone))
# define __opt_O1 __attribute__((optnone))
# define __opt_O2 __attribute__((optnone))
#elif defined(__GNUC__)
# define __opt_O0 __attribute__((optimize("-O0")))
# define __opt_O1 __attribute__((optimize("-O1")))
# define __opt_O2 __attribute__((optimize("-O2")))
#else
# define __opt_O0
# define __opt_O1
# define __opt_O2
#endif

#ifndef FALLTHROUGH
# ifdef HAVE_FALLTHROUGH
#  define FALLTHROUGH __attribute__((fallthrough))
# else
#  define FALLTHROUGH ((void)0)
# endif
#endif
