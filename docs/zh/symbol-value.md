
## 缩略词

- PIE: Position-Independent-Executable


## 介绍

**如何解析 symbol 地址？**

GDB 的符号解析实现 [binutils-gdb](https://sourceware.org/git/binutils-gdb) 很有帮助，我们应该使用 `BFD` 来解析符号和重定位。


## Linux内核对ELF文件的内存映射

参见内核 `load_elf_binary()` 函数，它会将所有 `PT_LOAD` 部分加载到内存中，位置就是我们关心的。

```
load_bias = 0
vaddr = elf_ppnt->p_vaddr
if (ET_EXEC)
elif (ET_DYN)
	load_bias = Non-Zero Value (random)

elf_map(file, load_bias + vaddr, ...) {
	size = p_filesz + ELF_PAGEOFFSET(p_vaddr);
	off = p_offset - ELF_PAGEOFFSET(p_vaddr);
	addr = load_bias + p_vaddr
	addr = ELF_PAGESTART(addr);
	size = ELF_PAGEALIGN(size);
	vm_mmap(filep, addr, size, ..., off);
}
```


## 进程的 VMAs

在 `/proc/PID/maps` 中，我们可以看到进程的 VMA，内核会将 `PT_LOAD` 加载到内存中，而 `linker`（例如在 `x86_64` fedora40 上 `/lib64/ld-linux-x86-64.so.2`）将分离一些 vma。例如：

非 PIE hello 程序的 `PT_LOAD`

```bash
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x0000000000000650 0x0000000000000650  R      0x1000
  LOAD           0x0000000000001000 0x0000000000401000 0x0000000000401000
                 0x0000000000000379 0x0000000000000379  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000402000 0x0000000000402000
                 0x00000000000001d4 0x00000000000001d4  R      0x1000
  LOAD           0x0000000000002df8 0x0000000000403df8 0x0000000000403df8
                 0x0000000000000248 0x0000000000000260  RW     0x1000
```

我们用 gdb 启动 `hello`，然后在链接器的 `_dl_start()` 上 `break` 开始：

```
$ gdb ./hello
(gdb) b _dl_start
(gdb) r
Breakpoint 1, _dl_start (arg=0x7fffffffd830) at rtld.c:517
517	{
```

然后查看VMA：

```
$ cat /proc/$(pidof hello)/maps
00400000-00401000 r--p 00000000 08:10 3115204 /ulpatch/tests/hello/hello
00401000-00402000 r-xp 00001000 08:10 3115204 /ulpatch/tests/hello/hello
00402000-00403000 r--p 00002000 08:10 3115204 /ulpatch/tests/hello/hello
00403000-00405000 rw-p 00002000 08:10 3115204 /ulpatch/tests/hello/hello
```

然后，`continue`继续运行：

```
(gdb) continue
```

发现 VMA 发生变化：

```
$ cat /proc/$(pidof hello)/maps
00400000-00401000 r--p 00000000 08:10 3115204 /ulpatch/tests/hello/hello
00401000-00402000 r-xp 00001000 08:10 3115204 /ulpatch/tests/hello/hello
00402000-00403000 r--p 00002000 08:10 3115204 /ulpatch/tests/hello/hello
00403000-00404000 r--p 00002000 08:10 3115204 /ulpatch/tests/hello/hello
00404000-00405000 rw-p 00003000 08:10 3115204 /ulpatch/tests/hello/hello
```

为什么链接器将 vma`00403000-00405000 rw-p 00002000`拆分为两个不同的 vma`00403000-00404000 r--p 00002000`和`00404000-00405000 rw-p 00003000`？让我们看看 [glibc](https://sourceware.org/git/glibc) 源代码（我的版本 `glibc-2.40.9000-13-g22958014ab`）中链接器的调用堆栈。

```
_dl_start() {
  _dl_start_final() {
    _dl_sysdep_start() {
      dl_main(dl_main_args.phdr, dl_main_args.phnum, ...) {
        _dl_relocate_object() {
          _dl_protect_relro() {
            phdr = PT_GNU_RELRO
            start = PAGE_DOWN(load_bias + phdr->p_vaddr);
            end = PAGE_DOWN(load_bias + phdr->p_vaddr + phdr->p_memsz);
            if (start != end) {
              mprotect(start, end - start, PROT_READ);
            }
          }
        }
      }
    }
  }
}
```

让我们看看 PIE 程序。

```
555555554000-555555555000 r--p 00000000 08:10 3115207 /ulpatch/tests/hello/hello-pie
555555555000-555555556000 r-xp 00001000 08:10 3115207 /ulpatch/tests/hello/hello-pie
555555556000-555555557000 r--p 00002000 08:10 3115207 /ulpatch/tests/hello/hello-pie
555555557000-555555559000 rw-p 00002000 08:10 3115207 /ulpatch/tests/hello/hello-pie
```

跟踪 `mprotect(2)`：

```
mprotect(0x555555557000, 0x4096, PROT_READ);
```

```
555555554000-555555555000 r--p 00000000 08:10 3115207 /ulpatch/tests/hello/hello-pie
555555555000-555555556000 r-xp 00001000 08:10 3115207 /ulpatch/tests/hello/hello-pie
555555556000-555555557000 r--p 00002000 08:10 3115207 /ulpatch/tests/hello/hello-pie
555555557000-555555558000 r--p 00002000 08:10 3115207 /ulpatch/tests/hello/hello-pie
555555558000-555555559000 rw-p 00003000 08:10 3115207 /ulpatch/tests/hello/hello-pie
```

我们应该知道为什么 linker 将 `addr=0x555555557000，len=0x4096` 内存修改为只读。

正如我们在 `readelf -l /bin/bash` 输出中看到的，最后一个 `PT_LOAD` 程序头和 `PT_GNU_RELRO` 程序头中的 `.data.rel.ro` ，内核会将所有 `PT_LOAD` 加载到内存中，然后，GNU 链接器将通过 `mprotect(2)` 系统调用将 `.data.rel.ro` 设置为**只读**权限，参见上面显示的链接器伪代码。因此，虚拟机 `555555557000-5555555559000 rw-p 00002000` 将拆分为两个不同的虚拟机 `55555557000-5555555558000 r--p 00002000` 和 `5555555558000-5555555559000 rw-p 00003000`。


## Links

- https://reverseengineering.stackexchange.com/questions/16036/how-can-i-view-the-dynamic-symbol-table-of-a-running-process
- https://jvns.ca/blog/2018/01/09/resolving-symbol-addresses/
- [How gdb loads symbol files](https://sourceware.org/gdb/wiki/How%20gdb%20loads%20symbol%20files)
- GitHub: [bpftrace](https://github.com/bpftrace/bpftrace)
