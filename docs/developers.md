## ULPatch Development Guide

This document features basic guidelines and recommendations on how to do ulpatch development. Please read it carefully before submitting patches to simplify reviewing and to speed up the merge process.


### Background

In my opinion, if you want to develop and participate in the development of this project together, the following knowledge points need to be understood in advance:

- Linux Basics;
- ELF format;
- ELF relocation;
- How Linux kernel runs an ELF executable;
- How GNU linker works;


### Precautions

You can view unfinished development tasks in [TODO-List](./TODO.md), and you need to obey the [Coding Style](./code-style.md) and [Contributing](./CONTRIBUTING.md) rules.


### C Compile Macros

#### CONFIG_CAPSTONE

Macro `CONFIG_CAPSTONE` defined and set to `1` by default if found capstone, you can turn it off, see [INSTALL](./INSTALL.md).


### C Macros

#### current

Like kernel macro `current`, this `current` indicates the currently opened remote process.
