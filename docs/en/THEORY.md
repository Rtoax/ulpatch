---
hide:
  - navigation
---

## Theroy

This page only introduce theroy of ULPatch, but not the implementation details.

All programs are single-threaded models, so you will not see synchronization locks in the code. Of course, we need to consider the multi-threaded situation of the target process.


## ULPatch

### Patch

The following figure shows the livepatch loading procedures.

![ulpatch::patch](images/ulpatch-patch.drawio.svg)

The detailed steps are as follows:

1. Compile source code into a relocatable ELF file, it's livepatch file;
2. Load the relocatable ELF file into the target process address space;
3. Relocate the symbols in the patch according to the target process address symbol table;
4. Modify the patch function entry to jump to the patch function;

The start instruction of the objective function will be replaced with the jump instruction that jumps to the patch function, as shown in the following figure:

![ulpatch::callee](images/ulpatch-func-trampoline.drawio.svg)


### Unpatch

The following figure shows the uninstall procedures of the livepatch.

![ulpatch::unpatch](images/ulpatch-unpatch.drawio.svg)

The `unpatch` operation is the reverse operation of `patch`, but without the relocate process.


## ULTask

It's an useful tool to modify target process, I call it **Program Modifier**. `CONFIG_BUILD_ULTASK` decides whether to compile `ultask`. Check manual `ultask(8)` to see more.

ULTask uses the `/proc/` file system to modify and view the target process. For example, read or modify the target process memory via `/proc/PID/mem`.

TODO


## ULFtrace

Same as [linux ftrace](https://www.kernel.org/doc/html/latest/trace/ftrace.html), need gcc `-pg` compile option. `CONFIG_BUILD_ULFTRACE` decides whether to compile `ulftrace`. Check manual `ulftrace(8)` to see more.

TODO
