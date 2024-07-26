---
hide:
  - navigation
---


## TODO

### Now

- Support load symbol-file like gdb.
- Some symbols will be optimized out.
- support Qemu
- support multi-thread and make each thread safety, use ptrace(2).
- Add ulpatches that already patched symbols to task symbols.
- Support uninitialized variable yet, see `.bss` `SHT_NOBITS`
- ULPatch VMA better isn't file map


### Further

- Support static executable ELF (no need to any dynamic libraries).
- Support sign and check.
- How to patch to strip ELF process.
- loongarch64 support.
- GUI support, like GTK/Qt, etc.


### No support (ideal is plump, reality is bony)

- Anon vma for each patch and use prctl(2)(`CONFIG_ANON_VMA_NAME`) set vma's name, and I try to submit kernel patch, but **David Hildenbrand** don't like it, see [LKML Link](https://lore.kernel.org/lkml/b2f4c084-47dc-4e92-a9e3-daec3f48425d@redhat.com/)
- Maybe we could use dlopen/dlsym to map ulpatch file.
