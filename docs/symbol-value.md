
## LSB executable

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
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
    [...]
    12: 0000000000404034     4 OBJECT  LOCAL  DEFAULT   24 keep_running
    13: 0000000000404048     8 OBJECT  LOCAL  DEFAULT   25 count
    14: 0000000000404038     4 OBJECT  LOCAL  DEFAULT   24 global_i
    15: 0000000000404050     1 OBJECT  LOCAL  DEFAULT   25 global_c
    16: 000000000040403c     4 OBJECT  LOCAL  DEFAULT   24 global_f
    17: 0000000000401176    41 FUNC    LOCAL  DEFAULT   14 sig_handler
    18: 000000000040119f    44 FUNC    LOCAL  DEFAULT   14 internal_print_hello
    19: 00000000004011cb    27 FUNC    LOCAL  DEFAULT   14 print_hello
    20: 00000000004011e6    79 FUNC    LOCAL  DEFAULT   14 routine
    [...]
    43: 0000000000401235   188 FUNC    GLOBAL DEFAULT   14 main
```

The symbol value in address space:

```bash
$ gdb -q -p $(pidof hello)
[...]
(gdb) p &keep_running
$1 = (sig_atomic_t *) 0x404034 <keep_running>
(gdb) p &global_i
$2 = (int *) 0x404038 <global_i>
(gdb) p sig_handler
$3 = {void (int)} 0x401176 <sig_handler>
(gdb) p internal_print_hello
$4 = {void (unsigned long)} 0x40119f <internal_print_hello>
(gdb) p print_hello
$5 = {void (unsigned long)} 0x4011cb <print_hello>
(gdb) p routine
$6 = {void *(void *)} 0x4011e6 <routine>
(gdb) p main
$7 = {int (int, char **)} 0x401235 <main>
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
maps:	0x0000000000400000
ELF:	0x00000000004011cb
GDB:	0x00000000004011cb
```

and the variable `global_i` addresses be like:

```bash
maps:	0x0000000000400000
ELF:	0x0000000000404038
GDB:	0x0000000000404038
```


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
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
    [...]
    12: 000000000000403c     4 OBJECT  LOCAL  DEFAULT   25 keep_running
    13: 0000000000004050     8 OBJECT  LOCAL  DEFAULT   26 count
    14: 0000000000004040     4 OBJECT  LOCAL  DEFAULT   25 global_i
    15: 0000000000004058     1 OBJECT  LOCAL  DEFAULT   26 global_c
    16: 0000000000004044     4 OBJECT  LOCAL  DEFAULT   25 global_f
    17: 0000000000001189    46 FUNC    LOCAL  DEFAULT   14 sig_handler
    18: 00000000000011b7    49 FUNC    LOCAL  DEFAULT   14 internal_print_hello
    19: 00000000000011e8    27 FUNC    LOCAL  DEFAULT   14 print_hello
    20: 0000000000001203    79 FUNC    LOCAL  DEFAULT   14 routine
    [...]
    43: 0000000000001252   225 FUNC    GLOBAL DEFAULT   14 main
```

The symbol value in address space:

```bash
$ gdb -q -p $(pidof hello-pie)
[...]
(gdb) p &keep_running
$1 = (sig_atomic_t *) 0x56399fbf803c <keep_running>
(gdb) p &global_i
$2 = (int *) 0x56399fbf8040 <global_i>
(gdb) p sig_handler
$3 = {void (int)} 0x56399fbf5189 <sig_handler>
(gdb) p internal_print_hello
$4 = {void (unsigned long)} 0x56399fbf51b7 <internal_print_hello>
(gdb) p print_hello
$5 = {void (unsigned long)} 0x56399fbf51e8 <print_hello>
(gdb) p routine
$6 = {void *(void *)} 0x56399fbf5203 <routine>
(gdb) p main
$7 = {int (int, char **)} 0x56399fbf5252 <main>
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
maps:	0x000056399fbf4000
ELF:	0x00000000000011e8
GDB:	0x000056399fbf51e8
```

and the variable `global_i` addresses be like:

```bash
maps:	0x000056399fbf4000
ELF:	0x0000000000004040
GDB:	0x000056399fbf8040
```


### aarch64 PIE

The `PT_LOAD` in ELF file:

```bash
$ readelf -l /home/rongtao/Git/ulpatch/tests/hello/hello
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000cec 0x0000000000000cec  R E    0x10000
  LOAD           0x000000000000fdc0 0x000000000001fdc0 0x000000000001fdc0
                 0x00000000000002a4 0x00000000000002b8  RW     0x10000
```

The `PT_LOAD` in `VMA` address space:

```bash
$ cat /proc/$(pidof hello)/maps
5585750000-5585751000 r-xp 00000000 b3:02 1061352   /home/rongtao/Git/ulpatch/tests/hello/hello
558576f000-5585770000 r--p 0000f000 b3:02 1061352   /home/rongtao/Git/ulpatch/tests/hello/hello
5585770000-5585771000 rw-p 00010000 b3:02 1061352   /home/rongtao/Git/ulpatch/tests/hello/hello
```
The symbol value in ELF file:

```bash
$ readelf --syms /home/rongtao/Git/ulpatch/tests/hello/hello
Symbol table '.symtab' contains 128 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
    [...]
    62: 0000000000020060     4 OBJECT  LOCAL  DEFAULT   23 keep_running
    63: 0000000000020070     8 OBJECT  LOCAL  DEFAULT   24 count
    67: 0000000000000914    64 FUNC    LOCAL  DEFAULT   13 sig_handler
    68: 0000000000000954    56 FUNC    LOCAL  DEFAULT   13 internal_print_hello
    69: 000000000000098c    32 FUNC    LOCAL  DEFAULT   13 print_hello
    70: 00000000000009ac   100 FUNC    LOCAL  DEFAULT   13 routine
    [...]
   120: 0000000000000a10   228 FUNC    GLOBAL DEFAULT   13 main
```

The symbol value in address space:

```bash
$ gdb -q -p $(pidof hello)
[...]
(gdb) p sig_handler
$1 = {void (int)} 0x5585750914 <sig_handler>
(gdb) p internal_print_hello
$2 = {void (unsigned long)} 0x5585750954 <internal_print_hello>
(gdb) p print_hello
$3 = {void (unsigned long)} 0x558575098c <print_hello>
(gdb) p routine
$4 = {void *(void *)} 0x55857509ac <routine>
(gdb) p main
$5 = {int (int, char **)} 0x5585750a10 <main>
```

And the auxiliary vector:

```bash
$ ultask -p $(pidof hello) --auxv
TYPE     VALUE
AT_PHDR  0x5585750040
AT_BASE  0x7f8c1de000
AT_ENTRY 0x5585750800
```

For example `print_hello`:

```bash
maps:	0x0000005585750000
ELF:	0x000000000000098c
GDB:	0x000000558575098c
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
