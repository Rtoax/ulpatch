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


### CMake Compile Macros

see [INSTALL](./INSTALL.md).


### C Macros

#### current

Like kernel macro `current`, this `current` indicates the currently opened remote process.


### C Functions

ULpatch functions set `errno` for bad situation.


### GitHub CI

Check [ulpatch/.github](https://github.com/Rtoax/ulpatch/tree/master/.github/workflows).
