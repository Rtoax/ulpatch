
## Abbreviations

- PIE: Position-Independent-Executable
- KASLR: Kernel Address Space Layout Randomize


## Introductions

**How to resolve symbol addresses?**

GDB's implementation of symbol parsing, [binutils-gdb](https://sourceware.org/git/binutils-gdb) is helpful, we should use `BFD` for resolve symbols and relocations.


## KASLR (Kernel Address Space Layout Randomize)

Because of Linux's built-in Kaslr technology, PIE processes and dynamic libraries will be loaded to a random offset address, and we need to add this offset to all symbols. See `/proc/PID/maps`.


## Links

- https://reverseengineering.stackexchange.com/questions/16036/how-can-i-view-the-dynamic-symbol-table-of-a-running-process
- https://jvns.ca/blog/2018/01/09/resolving-symbol-addresses/
- [How gdb loads symbol files](https://sourceware.org/gdb/wiki/How%20gdb%20loads%20symbol%20files)
- GitHub: [bpftrace](https://github.com/bpftrace/bpftrace)
