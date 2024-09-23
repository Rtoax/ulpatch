// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */

#ifdef TEST_SYM_FOR_EACH
# ifndef TEST_SYM_FOR_EACH_I
#  error "Need define TEST_SYM_FOR_EACH_I"
# endif
# ifndef TEST_SYM_ARRAY_NAME
#  error "Need define TEST_SYM_ARRAY_NAME"
# endif
for (TEST_SYM_FOR_EACH_I = 0;
	 TEST_SYM_FOR_EACH_I < ARRAY_SIZE(TEST_SYM_ARRAY_NAME);
	 TEST_SYM_FOR_EACH_I++) {
#endif

TEST_DATA_SYM(stdin)
TEST_DATA_SYM(stdout)
TEST_DATA_SYM(stderr)

/* stdlib.h */
TEST_FUNC_SYM(exit)
TEST_FUNC_SYM(system)

/* stdio.h */
TEST_FUNC_SYM(puts)
TEST_FUNC_SYM(printf)
TEST_FUNC_SYM(sprintf)
TEST_FUNC_SYM(snprintf)
TEST_FUNC_SYM(vprintf)
TEST_FUNC_SYM(vsprintf)
TEST_FUNC_SYM(vsnprintf)

/* sys/socket.h */
TEST_FUNC_SYM(socket)
TEST_FUNC_SYM(socketpair)
TEST_FUNC_SYM(getsockname)
TEST_FUNC_SYM(getpeername)
TEST_FUNC_SYM(connect)
TEST_FUNC_SYM(bind)
TEST_FUNC_SYM(send)
TEST_FUNC_SYM(sendto)
TEST_FUNC_SYM(sendmsg)
TEST_FUNC_SYM(recv)
TEST_FUNC_SYM(recvfrom)
TEST_FUNC_SYM(recvmsg)
TEST_FUNC_SYM(getsockopt)
TEST_FUNC_SYM(setsockopt)
TEST_FUNC_SYM(listen)
TEST_FUNC_SYM(accept)
TEST_FUNC_SYM(shutdown)

/* unistd.h */
TEST_FUNC_SYM(access)
TEST_FUNC_SYM(lseek)
TEST_FUNC_SYM(close)
TEST_FUNC_SYM(read)
TEST_FUNC_SYM(write)
TEST_FUNC_SYM(pread)
TEST_FUNC_SYM(pwrite)
TEST_FUNC_SYM(pipe)
TEST_FUNC_SYM(pipe)
TEST_FUNC_SYM(alarm)
TEST_FUNC_SYM(sleep)
TEST_FUNC_SYM(usleep)
TEST_FUNC_SYM(chown)
TEST_FUNC_SYM(fchown)
TEST_FUNC_SYM(getcwd)
TEST_FUNC_SYM(dup)
TEST_FUNC_SYM(dup2)
TEST_FUNC_SYM(dup3)
TEST_FUNC_SYM(execve)
TEST_FUNC_SYM(execv)
TEST_FUNC_SYM(execle)
TEST_FUNC_SYM(execl)
TEST_FUNC_SYM(execvp)
TEST_FUNC_SYM(execlp)
TEST_FUNC_SYM(nice)
TEST_FUNC_SYM(pathconf)
TEST_FUNC_SYM(sysconf)
TEST_FUNC_SYM(getpid)
TEST_FUNC_SYM(getppid)
TEST_FUNC_SYM(getpgrp)
TEST_FUNC_SYM(getpgid)
TEST_FUNC_SYM(setpgid)
TEST_FUNC_SYM(setpgrp)
TEST_FUNC_SYM(setsid)
TEST_FUNC_SYM(getuid)
TEST_FUNC_SYM(geteuid)
TEST_FUNC_SYM(getgid)
TEST_FUNC_SYM(getegid)
TEST_FUNC_SYM(getgroups)
TEST_FUNC_SYM(setuid)
TEST_FUNC_SYM(fork)
TEST_FUNC_SYM(vfork)
TEST_FUNC_SYM(ttyname)
TEST_FUNC_SYM(isatty)
TEST_FUNC_SYM(link)
TEST_FUNC_SYM(symlink)
TEST_FUNC_SYM(readlink)
TEST_FUNC_SYM(unlink)
TEST_FUNC_SYM(rmdir)
TEST_FUNC_SYM(gethostname)
TEST_FUNC_SYM(sethostname)
TEST_FUNC_SYM(daemon)
TEST_FUNC_SYM(chroot)
TEST_FUNC_SYM(fsync)
TEST_FUNC_SYM(sync)
TEST_FUNC_SYM(truncate)
TEST_FUNC_SYM(ftruncate)
TEST_FUNC_SYM(brk)
TEST_FUNC_SYM(sbrk)
TEST_FUNC_SYM(syscall)

/* ftrace relate */
#if defined(__x86_64__)
TEST_FUNC_SYM(mcount)
#elif defined(__aarch64__)
TEST_FUNC_SYM(_mcount)
#endif

/* ulpatch_test */
TEST_FUNC_SYM(main)
TEST_FUNC_SYM(who_am_i)
#ifdef TODO_TEST_STT_OBJECT
TEST_FUNC_SYM(test_list)
#endif

TEST_FUNC_SYM(static_func1)

#ifdef TEST_SYM_FOR_EACH
}
# undef TEST_SYM_FOR_EACH_I
#endif

