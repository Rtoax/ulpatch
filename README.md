ULPatch
========

# Introduction

ULPatch is open source user space live patch tool.


# Support Architecture

- [ ] `x86_64`: ready to go
- [ ] `aarch64`: ready to go


# Theroy

## ULPatch

![ulpatch](docs/images/ulpatch.svg)


## Ftrace

Same as [linux](https://github.com/torvalds/linux) ftrace, need gcc `-pg` compile option.
`BUILD_ULFTRACE` decides whether to compile `ulftrace`.


# Code Style

* VIM

```bash
# .vimrc
set tabstop=8
set softtabstop=8
set shiftwidth=8
```

