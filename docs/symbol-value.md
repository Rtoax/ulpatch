
## Abbreviations

- PIE: Position-Independent-Executable


## Kernel UProbes

### Function Address

- Q: How bpftrace uprobe get symbol addresses?

That's right, we can refer to bpftrace's implementation of uprobe, how to convert symbols into virtual addresses.

In bpftrace uprobe/uretprobe, `semantic_analyser.cpp` call `CreateUSym()`, then, call `CreateUInt64()` to create a `unsigned long` to store virtual address. Such as [tools/bashreadline.bt](https://github.com/bpftrace/bpftrace/blob/master/tools/bashreadline.bt) probe `uretprobe:/bin/bash:readline`

- A: Bpftrace only get the address in ELF file.

```
$ objdump -T /bin/bash | grep -w readline
00000000000d1c70 g    DF .text	00000000000000c9  Base        readline
```

We just echo `p:uprobes/readline /bin/bash:0x00000000000d1c70 %ip %ax` to `/sys/kernel/debug/tracing/uprobe_events` could attach this uprobe.

- Q: How kernel swap addr in ELF to addr in Memory?

Like address in ELF:/bin/bash `0xd1c70` to `0x56212afc2c70` in memory(see gdb output)?

```
$ echo $SHELL
/bin/bash
$ gdb -q -p $$
(gdb) p readline
$1 = {<text variable, no debug info>} 0x56212afc2c70 <readline>
```

As for why the address is different, because bash is PIE, I won't repeat it here.

```
$ readelf -h /bin/bash
Type:   DYN (Position-Independent Executable file)
```

So, let's read the kernel code in [5.10.13](https://github.com/Rtoax/linux-5.10.13)!!!

```
static unsigned long offset_to_vaddr(struct vm_area_struct *vma, loff_t offset)
{
	return vma->vm_start + offset - ((loff_t)vma->vm_pgoff << PAGE_SHIFT);
}
```

That's it, bingo!

Check the process VMAs:

```
$ cat /proc/$$/maps
56212aef1000-56212af13000 r--p 00000000 103:03 4212 /usr/bin/bash
56212af13000-56212b002000 r-xp 00022000 103:03 4212 /usr/bin/bash
56212b002000-56212b037000 r--p 00111000 103:03 4212 /usr/bin/bash
56212b037000-56212b03b000 r--p 00145000 103:03 4212 /usr/bin/bash
56212b03b000-56212b044000 rw-p 00149000 103:03 4212 /usr/bin/bash
```

We could get `readline()` addresses:

```
vm_start = 0x56212af13000
offset   = 0x0000000d1c70
pgoff    = 0x000000022000
pagesize = 4096
vm_pgoff = 34
vaddr    = 0x56212afc2c70
```

Calculate by `offset_to_vaddr()`:

```
$ printf '0x%lx\n' $((0x56212af13000 + 0x0000000d1c70  - $((34 << 12))))
0x56212afc2c70
```

It's correct!


### Data Address

We just use tests/hello/hello command as example.

Data address in no-PIE ELF file:

```
$ readelf --syms /ulpatch/tests/hello/hello | grep global_i
    14: 0000000000404038     4 OBJECT  LOCAL  DEFAULT   25 global_i
```

Data address in no-PIE ELF memory:

```
$ gdb -p $(pidof hello)
(gdb) p &global_i
$2 = (int *) 0x404038 <global_i>
```

`hello` vmas:

```
$ cat /proc/$(pidof hello)/maps
00400000-00401000 r--p 00000000 08:10 2641500 /ulpatch/tests/hello/hello
00401000-00402000 r-xp 00001000 08:10 2641500 /ulpatch/tests/hello/hello
00402000-00403000 r--p 00002000 08:10 2641500 /ulpatch/tests/hello/hello
00403000-00404000 r--p 00002000 08:10 2641500 /ulpatch/tests/hello/hello
00404000-00405000 rw-p 00003000 08:10 2641500 /ulpatch/tests/hello/hello
```

List all `global_i` addresses:

```
vm_start = 0x404000
offset   = 0x404038
pgoff    = 0x003000
vm_pgoff =        3
vaddr    = 0x404038
```

As you can see from the above address, if it is a non-PIE, you can directly use the offset in the ELF file.

If is PIE ELF, like `tests/hello/hello-pie`, data address in PIE ELF file:

```
$ readelf --syms /ulpatch/tests/hello/hello-pie | grep global_i
    14: 0000000000004040     4 OBJECT  LOCAL  DEFAULT   26 global_i
```

Data address in PIE ELF memory:

```
$ gdb -p $(pidof hello-pie)
(gdb) p &global_i
$2 = (int *) 0x559d2c798040 <global_i>
```

`hello-pie` vmas:

```
$ cat /proc/$(pidof hello-pie)/maps
559d2c794000-559d2c795000 r--p 00000000 08:00 2172938143 /ulpatch/tests/hello/hello-pie
559d2c795000-559d2c796000 r-xp 00001000 08:00 2172938143 /ulpatch/tests/hello/hello-pie
559d2c796000-559d2c797000 r--p 00002000 08:00 2172938143 /ulpatch/tests/hello/hello-pie
559d2c797000-559d2c798000 r--p 00002000 08:00 2172938143 /ulpatch/tests/hello/hello-pie
559d2c798000-559d2c799000 rw-p 00003000 08:00 2172938143 /ulpatch/tests/hello/hello-pie
```

List all `global_i` addresses:

```
vm_start = 0x559d2c798000
offset   = 0x000000004040
pgoff    = 0x000000003000
vm_pgoff =              3
vaddr    = 0x559d2c798040
```

TODO: `offset_to_vaddr()` could not swap `0x559d2c798000` to `0x559d2c798040`.


## LSB Executable

### non-PIE

The `PT_LOAD` in ELF file:

```bash
$ readelf -l /ulpatch/tests/hello/hello
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x0000000000000640 0x0000000000000640  R      0x1000
  LOAD           0x0000000000001000 0x0000000000401000 0x0000000000401000
                 0x0000000000000301 0x0000000000000301  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000402000 0x0000000000402000
                 0x00000000000001ac 0x00000000000001ac  R      0x1000
  LOAD           0x0000000000002df8 0x0000000000403df8 0x0000000000403df8
                 0x0000000000000248 0x0000000000000260  RW     0x1000
```

The `PT_LOAD` in `VMA` address space:

```bash
$ cat /proc/$(pidof hello)/maps
00400000-00401000 r--p 00000000 08:10 728777 /ulpatch/tests/hello/hello
00401000-00402000 r-xp 00001000 08:10 728777 /ulpatch/tests/hello/hello
00402000-00403000 r--p 00002000 08:10 728777 /ulpatch/tests/hello/hello
00403000-00404000 r--p 00002000 08:10 728777 /ulpatch/tests/hello/hello
00404000-00405000 rw-p 00003000 08:10 728777 /ulpatch/tests/hello/hello
```

The symbol value in ELF file:

```bash
$ readelf --syms /ulpatch/tests/hello/hello
Symbol table '.symtab' contains 46 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
    14: 0000000000404038     4 OBJECT  LOCAL  DEFAULT   24 global_i
    19: 00000000004011cb    27 FUNC    LOCAL  DEFAULT   14 print_hello
```

The symbol value in address space:

```bash
$ gdb -q -p $(pidof hello)
(gdb) p &global_i
$2 = (int *) 0x404038 <global_i>
(gdb) p print_hello
$5 = {void (unsigned long)} 0x4011cb <print_hello>
```

And the auxiliary vector:

```bash
$ ultask -p $(pidof hello) --auxv
TYPE     VALUE
AT_PHDR  0x400040
AT_BASE  0x7f6fcf1bb000
AT_ENTRY 0x401090
```

For example, the function `print_hello` addresses be like:

```bash
vm_start = 0x400000
offset   = 0x4011cb
vaddr    = 0x4011cb
```

And the variable `global_i` addresses be like:

```bash
vm_start = 0x400000
offset   = 0x404038
vaddr    = 0x404038
```

As we could see, the PIE ELF process, ELF `offset` in ELF file equal to `vaddr`.


### PIE

The `PT_LOAD` in ELF file:

```bash
$ readelf -l /ulpatch/tests/hello/hello-pie
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000788 0x0000000000000788  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x0000000000000341 0x0000000000000341  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
                 0x000000000000018c 0x000000000000018c  R      0x1000
  LOAD           0x0000000000002dc0 0x0000000000003dc0 0x0000000000003dc0
                 0x0000000000000288 0x00000000000002a0  RW     0x1000
```

The `PT_LOAD` in `VMA` address space:

```bash
$ cat /proc/$(pidof hello-pie)/maps
56399fbf4000-56399fbf5000 r--p 00000000 08:10 728782 /ulpatch/tests/hello/hello-pie
56399fbf5000-56399fbf6000 r-xp 00001000 08:10 728782 /ulpatch/tests/hello/hello-pie
56399fbf6000-56399fbf7000 r--p 00002000 08:10 728782 /ulpatch/tests/hello/hello-pie
56399fbf7000-56399fbf8000 r--p 00002000 08:10 728782 /ulpatch/tests/hello/hello-pie
56399fbf8000-56399fbf9000 rw-p 00003000 08:10 728782 /ulpatch/tests/hello/hello-pie
[...]
```

The symbol value in ELF file:

```bash
$ readelf --syms /ulpatch/tests/hello/hello-pie
Symbol table '.symtab' contains 46 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
    14: 0000000000004040     4 OBJECT  LOCAL  DEFAULT   25 global_i
    19: 00000000000011e8    27 FUNC    LOCAL  DEFAULT   14 print_hello
```

The symbol value in address space:

```bash
$ gdb -q -p $(pidof hello-pie)
(gdb) p &global_i
$2 = (int *) 0x56399fbf8040 <global_i>
(gdb) p print_hello
$5 = {void (unsigned long)} 0x56399fbf51e8 <print_hello>
```

And the auxiliary vector:

```bash
$ ultask -p $(pidof hello-pie) --auxv
TYPE     VALUE
AT_PHDR  0x56399fbf4040
AT_BASE  0x7fd420227000
AT_ENTRY 0x56399fbf50a0
```

For example, the function `print_hello` addresses be like:

```bash
vm_start = 0x56399fbf5000
offset   = 0x0000000011e8
pgoff    = 0x000000001000
vm_pgoff =              1
vaddr    = 0x56399fbf51e8
```

Calculate with `offset_to_vaddr()`

```
$ printf '0x%lx\n' $((0x000056399fbf5000 + 0x00000000000011e8 - $((1 << 12))))
0x56399fbf51e8
```

And the variable `global_i` addresses be like:

```bash
vm_start = 0x56399fbf8000
offset   = 0x000000004040
pgoff    = 0x000000003000
vm_pgoff =              3
vaddr    = 0x56399fbf8040
```


## Share library

TODO


## Links

- https://reverseengineering.stackexchange.com/questions/16036/how-can-i-view-the-dynamic-symbol-table-of-a-running-process
- https://jvns.ca/blog/2018/01/09/resolving-symbol-addresses/
- [How gdb loads symbol files](https://sourceware.org/gdb/wiki/How%20gdb%20loads%20symbol%20files)
- GitHub: [bpftrace](https://github.com/bpftrace/bpftrace)
