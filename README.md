UPatch
========

# Introduction

UPatch is open source ELF tool. Based on [elfutils](https://sourceware.org/git/elfutils.git).


# Support Architecture

- [ ] `x86_64`: ready to go
- [ ] `aarch64`: ready to go


# Theroy

## Ftrace

Same as [linux](https://github.com/torvalds/linux) ftrace, need gcc `-pg` compile option.
`BUILD_UFTRACE` decides whether to compile `uftrace`.


## Upatch

![upatch](docs/images/upatch.svg)


# Code Style

* VIM

```bash
# .vimrc
set tabstop=8
set softtabstop=8
set shiftwidth=8
```

