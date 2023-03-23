// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2023 CESTC, Co. Rong Tao <rongtao@cestc.cn> */

#ifdef TEST_SYM_FOR_EACH
# ifndef TEST_SYM_FOR_EACH_I
#  error "Need define TEST_SYM_FOR_EACH_I"
# endif
for (TEST_SYM_FOR_EACH_I = 0;
	 TEST_SYM_FOR_EACH_I < ARRAY_SIZE(test_symbols);
	 TEST_SYM_FOR_EACH_I++) {
#endif

/* Here start to define symbols */
/* not constant */
/* For example, if you try get 'stdout' address after process start running,
 * the value you get from VMA is not equal to the value you got from target
 * process directly. For 'stdout', you should get it's address from symbol
 * '_IO_2_1_stdout_', the gdb output like:
 *
 * (gdb) p stdout
 * $1 = (FILE *) 0x7ffff7f9d780 <_IO_2_1_stdout_>
 *
 * So, if we found the wrong value with symbol 'stdout', try '_IO_2_1_stdout_'
 * again, maybe we can get what we want.
 */
TEST_SYM_NON_STATIC(stdin, _IO_2_1_stdin_)
TEST_SYM_NON_STATIC(stdout, _IO_2_1_stdout_)
TEST_SYM_NON_STATIC(stderr, _IO_2_1_stderr_)

/* stdlib.h */
TEST_DYNSYM(exit)
TEST_DYNSYM(system)

/* stdio.h */
TEST_DYNSYM(printf)
TEST_DYNSYM(sprintf)
TEST_DYNSYM(snprintf)
TEST_DYNSYM(vprintf)
TEST_DYNSYM(vsprintf)
TEST_DYNSYM(vsnprintf)

/* sys/socket.h */
TEST_DYNSYM(socket)
TEST_DYNSYM(socketpair)
TEST_DYNSYM(getsockname)
TEST_DYNSYM(getpeername)
TEST_DYNSYM(connect)
TEST_DYNSYM(bind)
TEST_DYNSYM(send)
TEST_DYNSYM(sendto)
TEST_DYNSYM(sendmsg)
TEST_DYNSYM(recv)
TEST_DYNSYM(recvfrom)
TEST_DYNSYM(recvmsg)
TEST_DYNSYM(getsockopt)
TEST_DYNSYM(setsockopt)
TEST_DYNSYM(listen)
TEST_DYNSYM(accept)
TEST_DYNSYM(shutdown)

/* unistd.h */
TEST_DYNSYM(access)
TEST_DYNSYM(lseek)
TEST_DYNSYM(close)
TEST_DYNSYM(read)
TEST_DYNSYM(write)
TEST_DYNSYM(pread)
TEST_DYNSYM(pwrite)
TEST_DYNSYM(pipe)
TEST_DYNSYM(pipe)
TEST_DYNSYM(alarm)
TEST_DYNSYM(sleep)
TEST_DYNSYM(usleep)
TEST_DYNSYM(chown)
TEST_DYNSYM(fchown)
TEST_DYNSYM(getcwd)
TEST_DYNSYM(dup)
TEST_DYNSYM(dup2)
TEST_DYNSYM(dup3)
TEST_DYNSYM(execve)
TEST_DYNSYM(execv)
TEST_DYNSYM(execle)
TEST_DYNSYM(execl)
TEST_DYNSYM(execvp)
TEST_DYNSYM(execlp)
TEST_DYNSYM(nice)
TEST_DYNSYM(pathconf)
TEST_DYNSYM(sysconf)
TEST_DYNSYM(getpid)
TEST_DYNSYM(getppid)
TEST_DYNSYM(getpgrp)
TEST_DYNSYM(getpgid)
TEST_DYNSYM(setpgid)
TEST_DYNSYM(setpgrp)
TEST_DYNSYM(setsid)
TEST_DYNSYM(getuid)
TEST_DYNSYM(geteuid)
TEST_DYNSYM(getgid)
TEST_DYNSYM(getegid)
TEST_DYNSYM(getgroups)
TEST_DYNSYM(setuid)
TEST_DYNSYM(fork)
TEST_DYNSYM(vfork)
TEST_DYNSYM(ttyname)
TEST_DYNSYM(isatty)
TEST_DYNSYM(link)
TEST_DYNSYM(symlink)
TEST_DYNSYM(readlink)
TEST_DYNSYM(unlink)
TEST_DYNSYM(rmdir)
TEST_DYNSYM(gethostname)
TEST_DYNSYM(sethostname)
TEST_DYNSYM(daemon)
TEST_DYNSYM(chroot)
TEST_DYNSYM(fsync)
TEST_DYNSYM(sync)
TEST_DYNSYM(truncate)
TEST_DYNSYM(ftruncate)
TEST_DYNSYM(brk)
TEST_DYNSYM(sbrk)
TEST_DYNSYM(syscall)

/* ftrace relate */
#if defined(__x86_64__)
TEST_DYNSYM(mcount)
#elif defined(__aarch64__)
TEST_DYNSYM(_mcount)
#endif

/* upatch_test */
TEST_SYM_SELF(main)
TEST_SYM_SELF(who_am_i)
TEST_SYM_SELF(test_list)


#ifdef TEST_SYM_FOR_EACH
}
# undef TEST_SYM_FOR_EACH_I
#endif

