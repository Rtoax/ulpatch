
## LSB Executable

### x86_64 non-PIE

The `PT_LOAD` in ELF file:

```bash
$ readelf -l /home/rongtao/Git/ulpatch/tests/hello/hello
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
00400000-00401000 r--p 00000000 08:10 728777 /home/sdb/Git/ulpatch/tests/hello/hello
00401000-00402000 r-xp 00001000 08:10 728777 /home/sdb/Git/ulpatch/tests/hello/hello
00402000-00403000 r--p 00002000 08:10 728777 /home/sdb/Git/ulpatch/tests/hello/hello
00403000-00404000 r--p 00002000 08:10 728777 /home/sdb/Git/ulpatch/tests/hello/hello
00404000-00405000 rw-p 00003000 08:10 728777 /home/sdb/Git/ulpatch/tests/hello/hello
[...]
```

The symbol value in ELF file:

```bash
$ readelf --syms /home/rongtao/Git/ulpatch/tests/hello/hello
[...]
Symbol table '.symtab' contains 46 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
    14: 0000000000404038     4 OBJECT  LOCAL  DEFAULT   24 global_i
    19: 00000000004011cb    27 FUNC    LOCAL  DEFAULT   14 print_hello
```

The symbol value in address space:

```bash
$ gdb -q -p $(pidof hello)
[...]
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

There are two different situation. The first is the `p_vaddr != 0`, then the min address of `PT_LOAD` equal to `p_vaddr`.

For example, the function `print_hello` addresses be like:

```bash
vm_start = 0x0000000000400000
offset   = 0x00000000004011cb
vaddr    = 0x00000000004011cb
```

And the variable `global_i` addresses be like:

```bash
vm_start = 0x0000000000400000
offset   = 0x0000000000404038
vaddr    = 0x0000000000404038
```

As we could see, the PIE ELF process, ELF `offset` equal to `vaddr`.


### x86_64 PIE

The `PT_LOAD` in ELF file:

```bash
$ readelf -l /home/rongtao/Git/ulpatch/tests/hello/hello-pie
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
56399fbf4000-56399fbf5000 r--p 00000000 08:10 728782 /home/sdb/Git/ulpatch/tests/hello/hello-pie
56399fbf5000-56399fbf6000 r-xp 00001000 08:10 728782 /home/sdb/Git/ulpatch/tests/hello/hello-pie
56399fbf6000-56399fbf7000 r--p 00002000 08:10 728782 /home/sdb/Git/ulpatch/tests/hello/hello-pie
56399fbf7000-56399fbf8000 r--p 00002000 08:10 728782 /home/sdb/Git/ulpatch/tests/hello/hello-pie
56399fbf8000-56399fbf9000 rw-p 00003000 08:10 728782 /home/sdb/Git/ulpatch/tests/hello/hello-pie
[...]
```

The symbol value in ELF file:

```bash
$ readelf --syms /home/rongtao/Git/ulpatch/tests/hello/hello-pie
[...]
Symbol table '.symtab' contains 46 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
    14: 0000000000004040     4 OBJECT  LOCAL  DEFAULT   25 global_i
    19: 00000000000011e8    27 FUNC    LOCAL  DEFAULT   14 print_hello
```

The symbol value in address space:

```bash
$ gdb -q -p $(pidof hello-pie)
[...]
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
vm_start = 0x000056399fbf5000
offset   = 0x00000000000011e8
pgoff    = 0x0000000000001000
vm_pgoff =                  1
vaddr    = 0x000056399fbf51e8
```

Calculate with `offset_to_vaddr()`

```
$ printf '0x%lx\n' $((0x000056399fbf5000 + 0x00000000000011e8 - $((1 << 12))))
0x56399fbf51e8
```

And the variable `global_i` addresses be like:

```bash
vm_start = 0x000056399fbf8000
offset   = 0x0000000000004040
pgoff    = 0x0000000000003000
vm_pgoff =                  3
vaddr    = 0x000056399fbf8040
```


### aarch64 non-PIE

The `PT_LOAD` in ELF file:

```
$ readelf -l hello
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000400040 0x0000000000400040
                 0x0000000000000268 0x0000000000000268  R      0x8
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x0000000000000670 0x0000000000000670  R      0x10000
  LOAD           0x0000000000010000 0x0000000000410000 0x0000000000410000
                 0x000000000000042c 0x000000000000042c  R E    0x10000
  LOAD           0x0000000000020000 0x0000000000420000 0x0000000000420000
                 0x000000000000022c 0x000000000000022c  R      0x10000
  LOAD           0x000000000002fde8 0x000000000043fde8 0x000000000043fde8
                 0x0000000000000270 0x0000000000000288  RW     0x10000
```

The `PT_LOAD` in `VMA` address space:

```
$ cat /proc/$(pidof hello)/maps
00400000-00401000 r--p 00000000 00:23 69301 /home/rongtao/Git/ulpatch/tests/hello/hello
00410000-00411000 r-xp 00010000 00:23 69301 /home/rongtao/Git/ulpatch/tests/hello/hello
00420000-00421000 r--p 00020000 00:23 69301 /home/rongtao/Git/ulpatch/tests/hello/hello
0043f000-00440000 r--p 0002f000 00:23 69301 /home/rongtao/Git/ulpatch/tests/hello/hello
00440000-00441000 rw-p 00030000 00:23 69301 /home/rongtao/Git/ulpatch/tests/hello/hello
```

The symbol value in ELF file:

```
$ readelf --syms hello
Symbol table '.symtab' contains 136 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
    70: 0000000000440050     4 OBJECT  LOCAL  DEFAULT   23 global_i
    77: 00000000004102a4    32 FUNC    LOCAL  DEFAULT   13 print_hello
```

The symbol value in address space:

```bash
$ gdb -q -p $(pidof hello)
(gdb) p print_hello
$1 = {void (unsigned long)} 0x4102a4 <print_hello>
(gdb) p &global_i
$2 = (int *) 0x440050 <global_i>
```

The `print_hello()` function addresses:

```bash
vm_start = 0x00410000
offset   = 0x004102a4
vaddr    = 0x004102a4
```

The `global_i` addresses:

```bash
vm_start = 0x00440000
offset   = 0x00440050
vaddr    = 0x00440050
```


### aarch64 PIE

The `PT_LOAD` in ELF file:

```bash
$ readelf -l hello-pie
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x0000000000000268 0x0000000000000268  R      0x8
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000768 0x0000000000000768  R      0x10000
  LOAD           0x0000000000010000 0x0000000000010000 0x0000000000010000
                 0x0000000000000428 0x0000000000000428  R E    0x10000
  LOAD           0x0000000000020000 0x0000000000020000 0x0000000000020000
                 0x00000000000001f4 0x00000000000001f4  R      0x10000
  LOAD           0x000000000002fdb8 0x000000000003fdb8 0x000000000003fdb8
                 0x00000000000002a8 0x00000000000002c0  RW     0x10000
```

The `PT_LOAD` in `VMA` address space:

```bash
$ cat /proc/$(pidof hello-pie)/maps
aaaadc490000-aaaadc491000 r--p 00000000 00:23 69304 /home/rongtao/Git/ulpatch/tests/hello/hello-pie
aaaadc4a0000-aaaadc4a1000 r-xp 00010000 00:23 69304 /home/rongtao/Git/ulpatch/tests/hello/hello-pie
aaaadc4b0000-aaaadc4b1000 r--p 00020000 00:23 69304 /home/rongtao/Git/ulpatch/tests/hello/hello-pie
aaaadc4cf000-aaaadc4d0000 r--p 0002f000 00:23 69304 /home/rongtao/Git/ulpatch/tests/hello/hello-pie
aaaadc4d0000-aaaadc4d1000 rw-p 00030000 00:23 69304 /home/rongtao/Git/ulpatch/tests/hello/hello-pie
```

The symbol value in ELF file:

```bash
$ readelf --syms hello-pie
Symbol table '.symtab' contains 128 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
    68: 0000000000040058     4 OBJECT  LOCAL  DEFAULT   24 global_i
    75: 00000000000102a0    32 FUNC    LOCAL  DEFAULT   13 print_hello
```

The symbol value in address space:

```bash
$ gdb -q -p $(pidof hello-pie)
(gdb) p print_hello
$1 = {void (unsigned long)} 0xaaaadc4a02a0 <print_hello>
(gdb) p &global_i
$3 = (int *) 0xaaaadc4d0058 <global_i>
```

And the auxiliary vector:

```bash
$ ultask -p $(pidof hello) --auxv
TYPE     VALUE
AT_PHDR  0x5585750040
AT_BASE  0x7f8c1de000
AT_ENTRY 0x5585750800
```

Function `print_hello()` addresses:

```bash
vm_start = 0xaaaadc4a0000
offset   = 0x0000000102a0
pgoff    = 0x000000010000
vm_pgoff =             16
vaddr    = 0xaaaadc4a02a0
```

```
$ printf '0x%lx\n' $((0xaaaadc4a0000 + 0x0000000102a0 - $((16 << 12))))
0xaaaadc4a02a0
```

Variable `global_i` addresses:

```bash
vm_start = 0xaaaadc4d0000
offset   = 0x000000040058
pgoff    = 0x000000030000
vm_pgoff =             48
vaddr    = 0xaaaadc4d0058
```

### uprobe

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

Like address in ELF:/bin/bash `0x00000000000d1c70` to `0x55b3a3a93c70` in memory(see gdb output)?

```
$ echo $SHELL
/bin/bash
$ gdb -q -p $$
(gdb) print readline
$1 = {<text variable, no debug info>} 0x55b3a3a93c70 <readline>
```

As for why the address is different, because bash is PIE, I won't repeat it here.

```
$ readelf -h /bin/bash
Type:   DYN (Position-Independent Executable file)
```

So, let's read the kernel code in [5.10.13](https://github.com/Rtoax/linux-5.10.13)!!!

Register `uprobe_events`

```
init_uprobe_trace() {
  trace_create_file("uprobe_events", &uprobe_events_ops);
}
fs_initcall(init_uprobe_trace);
```

```
uprobe_events_ops.write = probes_write()
probes_write() {
  trace_parse_run_command(..., create_or_delete_trace_uprobe);
}
```

Finally, call `register_trace_uprobe()`

```
struct trace_uprobe *tu;
tu->offset = 0x00000000000d1c70;
tu->filename = /bin/bash;
register_trace_uprobe(tu);
```

`register_trace_uprobe()` will call `register_uprobe_event()`.

We don't seem to have found out how the symbolic address in the ELF file is translated into the virtual address of the process! Don't worry, let's look at `offset_to_vaddr()` function directly.

Let's check function `build_map_info()`, it's swap offset to virtual address.

```
static unsigned long offset_to_vaddr(struct vm_area_struct *vma, loff_t offset)
{
	return vma->vm_start + offset - ((loff_t)vma->vm_pgoff << PAGE_SHIFT);
}
```

That's it, bingo!


### Data Address

We just use tests/hello/hello command as example.

Data address in no-PIE ELF file:

```
$ readelf --syms hello | grep global_i
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
00400000-00401000 r--p 00000000 08:10 2641500 /home/sdb/Git/ulpatch/tests/hello/hello
00401000-00402000 r-xp 00001000 08:10 2641500 /home/sdb/Git/ulpatch/tests/hello/hello
00402000-00403000 r--p 00002000 08:10 2641500 /home/sdb/Git/ulpatch/tests/hello/hello
00403000-00404000 r--p 00002000 08:10 2641500 /home/sdb/Git/ulpatch/tests/hello/hello
00404000-00405000 rw-p 00003000 08:10 2641500 /home/sdb/Git/ulpatch/tests/hello/hello
```

List all `global_i` addresses:

```
vm_start = 0x00404000
offset   = 0x00404038
vm_pgoff = 0x00003000
vaddr    = 0x00404038
```

As you can see from the above address, if it is a non-PIE, you can directly use the offset in the ELF file.

If is PIE ELF, like `tests/hello/hello-pie`, data address in PIE ELF file:

```
$ readelf --syms hello-pie | grep global_i
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
559d2c794000-559d2c795000 r--p 00000000 08:00 2172938143 /home/sda/git-repos/ulpatch/tests/hello/hello-pie
559d2c795000-559d2c796000 r-xp 00001000 08:00 2172938143 /home/sda/git-repos/ulpatch/tests/hello/hello-pie
559d2c796000-559d2c797000 r--p 00002000 08:00 2172938143 /home/sda/git-repos/ulpatch/tests/hello/hello-pie
559d2c797000-559d2c798000 r--p 00002000 08:00 2172938143 /home/sda/git-repos/ulpatch/tests/hello/hello-pie
559d2c798000-559d2c799000 rw-p 00003000 08:00 2172938143 /home/sda/git-repos/ulpatch/tests/hello/hello-pie
```

List all `global_i` addresses:

```
vm_start = 0x559d2c798000
offset   = 0x000000004040
vm_pgoff = 0x000000003000
vaddr    = 0x559d2c798040
```

TODO: `offset_to_vaddr()` could not swap `0x000000004040` to `0x559d2c798040`.


## Share library

TODO


## Notes

- Must support PIE ELF(PIE: Position-Independent-Executable);


## Links

- https://reverseengineering.stackexchange.com/questions/16036/how-can-i-view-the-dynamic-symbol-table-of-a-running-process
- https://jvns.ca/blog/2018/01/09/resolving-symbol-addresses/
- [How gdb loads symbol files](https://sourceware.org/gdb/wiki/How%20gdb%20loads%20symbol%20files)
- GitHub: [bpftrace](https://github.com/bpftrace/bpftrace)
