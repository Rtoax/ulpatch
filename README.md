<center><a href="images/logo.drawio.svg"><img src="images/logo.drawio.svg" border=0 width=300></a></center>

# ULPatch: A tool for userspace live patch

![License GPL](images/License-GNU-GPL-blue.svg)
![License GPL 2.0](images/License-GNU-GPL-2.0.svg)
[![PRs](https://img.shields.io/badge/PRs-welcome-pink.svg)](https://github.com/Rtoax/ulpatch/pulls)
[![docs](https://img.shields.io/badge/docs-latest-blue)](https://rtoax.github.io/ulpatch/)

<br/>


# Introduction

ULPatch is open source user space live patch tool.


## Background

For a process like Qemu that cannot be interrupted and restarted, vulnerability fixing is very difficult. Especially for cloud vendors, the live patch function is very important.

Hot patching in the kernel is already a relatively mature technology. Implementing [livepatch](https://docs.kernel.org/livepatch/livepatch.html) based on ftrace in the [linux kernel](https://github.com/torvalds/linux). Of course, the ULPatch project only discusses user-mode programs.


## Related Projects

ULPatch draws on several excellent open source projects, such as [cloudlinux/libcare](https://github.com/cloudlinux/libcare), and Huawei’s secondary development [openeuler/libcareplus](https://gitee.com/openeuler/libcareplus). SUSE has also open sourced its own live patch solution [SUSE/libpulp](https://github.com/SUSE/libpulp).

At the same time, the implementation of the kernel's `finit_module(2)` and `init_module(2)` system calls is also of great reference value. Even in the early stages of development, the relocation code was transplanted from these two system calls.

How to resolve symbol addresses? For examples, the implementation of [uprobe in the linux kernel](https://docs.kernel.org/trace/uprobetracer.html). At the same time, the implementation of application-level software, such as the implementation of [BCC](https://github.com/iovisor/bcc) and [bpftrace](https://github.com/iovisor/bpftrace).

GDB’s implementation of symbol parsing, [binutils-gdb](https://sourceware.org/git/binutils-gdb) is helpful.

Judging from the current research on outstanding projects, the live patch function relies on modifying the assembly instructions at the function entrance to make it jump to a new function, thereby realizing the live patch function.

I think I should detail the inspiration of ULPatch from these open source projects in another document instead of a README file.

> I don't like to get involved in the License wars, so please forgive me if I misquote open source code. After all, this is not a commercial project.


# Support Architecture

Due to my limited personal experience, I can't understand and master all the architectures, here is a list of the architectures that I am familiar with or hope to support, if they do not contain what you need, you are welcome to co-develop.

- [ ] `x86_64`: ready to go
- [ ] `aarch64`: ready to go
- [ ] `loongarch64`: ready to go


# Installing

See [docs/INSTALL.md](docs/INSTALL.md) for installation steps on your platform.


# Theroy

## ULPatch

![ulpatch](docs/images/ulpatch.drawio.svg)


## ULFtrace

Same as [linux](https://github.com/torvalds/linux) ftrace, need gcc `-pg` compile option.
`BUILD_ULFTRACE` decides whether to compile `ulftrace`.


# Releases

See [docs/RELEASE.md](docs/RELEASE.md) for releases.


# Warnings

- Before you do it, it's best to know what you're doing.

