
## 缩略词

- PIE: Position-Independent-Executable
- KASLR: Kernel Address Space Layout Randomize


## 介绍

**如何解析 symbol 地址？**

GDB 的符号解析实现 [binutils-gdb](https://sourceware.org/git/binutils-gdb) 很有帮助，我们应该使用 `BFD` 来解析符号和重定位。


## KASLR (内核地址空间布局随机化)

因为linux内和的kaslr技术，PIE进程和动态库都将加载到一个随机偏移地址，我们需要对所有符号添加这个偏移量。参见`/proc/PID/maps`。


## Links

- https://reverseengineering.stackexchange.com/questions/16036/how-can-i-view-the-dynamic-symbol-table-of-a-running-process
- https://jvns.ca/blog/2018/01/09/resolving-symbol-addresses/
- [How gdb loads symbol files](https://sourceware.org/gdb/wiki/How%20gdb%20loads%20symbol%20files)
- GitHub: [bpftrace](https://github.com/bpftrace/bpftrace)
