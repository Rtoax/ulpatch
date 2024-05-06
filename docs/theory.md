---
hide:
  - navigation
---

## Theroy

This page will only introduce the principle of ULPatch, but not the implementation details.


## ULPatch

### Patch

The following figure shows the hot patch loading process.

![ulpatch](images/ulpatch-patch.drawio.svg)

The detailed steps are as follows:

1. Compile source code into a relocatable ELF file;
2. Load the relocatable ELF file into the target process address space;
3. Relocate the symbols in the patch according to the target process address symbol table;
4. Modify the patch function entry to jump to the patch function;


### Unpatch

The following figure shows the uninstall process of the hot patch.

![ulpatch::unpatch](images/ulpatch-unpatch.drawio.svg)

The `unpatch` operation is the reverse operation of `patch`, but without the relocate process.


## ULFtrace

Same as [linux ftrace](https://www.kernel.org/doc/html/latest/trace/ftrace.html), need gcc `-pg` compile option.
`BUILD_ULFTRACE` decides whether to compile `ulftrace`.

