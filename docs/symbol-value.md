
## Abbreviations

- PIE: Position-Independent-Executable


## Kernel ELF File Map

See kernel `load_elf_binary()` function, it will load all `PT_LOAD` section to memory, the location is what we care about.

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

### non-PIE

And example of `elf_map()` tracing of non-PIE:

```bash
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x00000000000006c8 0x00000000000006c8  R      0x1000
  LOAD           0x0000000000001000 0x0000000000401000 0x0000000000401000
                 0x0000000000000379 0x0000000000000379  R E    0x1000

  # .rodata .eh_frame_hdr .eh_frame
  LOAD           0x0000000000002000 0x0000000000402000 0x0000000000402000
                 0x00000000000001d4 0x00000000000001d4  R      0x1000

  # .init_array .fini_array .dynamic .got .got.plt .data .bss
  LOAD           0x0000000000002e00 0x0000000000403e00 0x0000000000403e00
                 0x0000000000000258 0x0000000000000270  RW     0x1000

$ sudo ./elf_map.bt  | grep hello
TIME     PID      ADDR(e)          SIZE(e)  PROT ADDR(m)          SIZE(m)  OFF              MAP ADDR         COMM
16:33:52 205279   400000           0        r--- 400000           1000     0               400000           hello
16:33:52 205279   401000           0        r-x- 401000           1000     1000            401000           hello
16:33:52 205279   402000           0        r--- 402000           1000     2000            402000           hello
16:33:52 205279   403e00           0        rw-- 403000           2000     2000            403000           hello

MAP1: 400000 - 4006c8
MAP2: 401000 - 401379
MAP3: 402000 - 4021d4
MAP4: 403e00 - 404170

00400000-00401000 r--p 00000000 fd:03 202332043 /ulpatch/tests/hello/hello
00401000-00402000 r-xp 00001000 fd:03 202332043 /ulpatch/tests/hello/hello
00402000-00403000 r--p 00002000 fd:03 202332043 /ulpatch/tests/hello/hello
00403000-00404000 r--p 00002000 fd:03 202332043 /ulpatch/tests/hello/hello
00404000-00405000 rw-p 00003000 fd:03 202332043 /ulpatch/tests/hello/hello
```


### PIE (hello-pie)

And example of `elf_map()` tracing of PIE:

```bash
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000778 0x0000000000000778  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x00000000000003c5 0x00000000000003c5  R E    0x1000

  # .rodata .eh_frame_hdr .eh_frame
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
                 0x00000000000001ac 0x00000000000001ac  R      0x1000

  # .init_array .fini_array .data.rel.ro .dynamic .got .got.plt .data .bss
  LOAD           0x0000000000002dd8 0x0000000000003dd8 0x0000000000003dd8
                 0x0000000000000288 0x00000000000002a0  RW     0x1000

TIME     PID      ADDR(e)          SIZE(e)  PROT ADDR(m)          SIZE(m)  OFF             MAP ADDR         COMM
16:35:30 205810   55cc6668e000     4078     r--- 55cc6668e000     5000     0               55cc6668e000     hello-pie
16:35:30 205810   55cc6668f000     0        r-x- 55cc6668f000     1000     1000            55cc6668f000     hello-pie
16:35:30 205810   55cc66690000     0        r--- 55cc66690000     1000     2000            55cc66690000     hello-pie
16:35:30 205810   55cc66691dd8     0        rw-- 55cc66691000     2000     2000            55cc66691000     hello-pie

55cc6668e000-55cc6668f000 r--p 00000000 fd:03 202332046 /ulpatch/tests/hello/hello-pie
55cc6668f000-55cc66690000 r-xp 00001000 fd:03 202332046 /ulpatch/tests/hello/hello-pie
55cc66690000-55cc66691000 r--p 00002000 fd:03 202332046 /ulpatch/tests/hello/hello-pie
55cc66691000-55cc66692000 r--p 00002000 fd:03 202332046 /ulpatch/tests/hello/hello-pie
55cc66692000-55cc66693000 rw-p 00003000 fd:03 202332046 /ulpatch/tests/hello/hello-pie
```


### PIE (bash)

And example of `elf_map()` tracing of bash(is PIE):

```
$ readelf -l /usr/bin/bash

Elf file type is DYN (Shared object file)
Entry point 0x31d30
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x000000000002dd58 0x000000000002dd58  R      0x1000
  LOAD           0x000000000002e000 0x000000000002e000 0x000000000002e000
                 0x00000000000da4d5 0x00000000000da4d5  R E    0x1000
  LOAD           0x0000000000109000 0x0000000000109000 0x0000000000109000
                 0x0000000000038a74 0x0000000000038a74  R      0x1000
  LOAD           0x0000000000141c10 0x0000000000142c10 0x0000000000142c10
                 0x000000000000ba80 0x0000000000016a48  RW     0x1000

TIME     PID      ADDR(e)          SIZE(e)  PROT ADDR(m)          SIZE(m)  OFF             MAP ADDR         COMM
17:29:44 215642   5650ca62c000     159658   r--- 5650ca62c000     15a000   0               5650ca62c000     bash
17:29:44 215642   5650ca65a000     0        r-x- 5650ca65a000     db000    2e000           5650ca65a000     bash
17:29:44 215642   5650ca735000     0        r--- 5650ca735000     39000    109000          5650ca735000     bash
17:29:44 215642   5650ca76ec10     0        rw-- 5650ca76e000     d000     141000          5650ca76e000     bash

$ cat /proc/$$/maps
5650ca62c000-5650ca65a000 r--p 00000000 fd:03 201680556     /usr/bin/bash
5650ca65a000-5650ca735000 r-xp 0002e000 fd:03 201680556     /usr/bin/bash
5650ca735000-5650ca76e000 r--p 00109000 fd:03 201680556     /usr/bin/bash
5650ca76e000-5650ca772000 r--p 00141000 fd:03 201680556     /usr/bin/bash
5650ca772000-5650ca77b000 rw-p 00145000 fd:03 201680556     /usr/bin/bash
```

It can be seen that the mappings have overlapping parts, which can be verified in this way.

```
$ printf '0x%lx\n' $(( 0x5650ca735000 + $((0x00141000 - 0x00109000)) ))
0x5650ca76d000

$ ultask -p $$ --dump-addr 0x5650ca76d000 --dump-size 4096 -o a.elf
$ hexdump -C a.elf | head -5
00000000  18 42 0e 10 42 0e 08 47  0b 00 00 00 60 00 00 00  |.B..B..G....`...|
00000010  38 a1 01 00 5c dc fb ff  78 01 00 00 00 46 0e 10  |8...\...x....F..|
00000020  8f 02 47 0e 18 8e 03 42  0e 20 8d 04 46 0e 28 8c  |..G....B. ..F.(.|
00000030  05 48 0e 30 86 06 44 0e  38 83 07 4f 0e 50 03 1e  |.H.0..D.8..O.P..|
00000040  01 0a 0e 38 41 0e 30 41  0e 28 42 0e 20 42 0e 18  |...8A.0A.(B. B..|

$ ultask -p $$ --dump-addr 0x5650ca76e000 --dump-size 4096 -o b.elf
$ hexdump -C b.elf | head -5
00000000  18 42 0e 10 42 0e 08 47  0b 00 00 00 60 00 00 00  |.B..B..G....`...|
00000010  38 a1 01 00 5c dc fb ff  78 01 00 00 00 46 0e 10  |8...\...x....F..|
00000020  8f 02 47 0e 18 8e 03 42  0e 20 8d 04 46 0e 28 8c  |..G....B. ..F.(.|
00000030  05 48 0e 30 86 06 44 0e  38 83 07 4f 0e 50 03 1e  |.H.0..D.8..O.P..|
00000040  01 0a 0e 38 41 0e 30 41  0e 28 42 0e 20 42 0e 18  |...8A.0A.(B. B..|
```


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
offset   = 0x0000000d1c70 (st_value)
off      = 0x000000022000
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
offset   = 0x404038 (st_value)
off      = 0x003000
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
offset   = 0x000000004040 (st_value)
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
offset   = 0x4011cb (st_value)
vaddr    = 0x4011cb
```

And the variable `global_i` addresses be like:

```bash
vm_start = 0x400000
offset   = 0x404038 (st_value)
vaddr    = 0x404038
```

As we could see, the PIE ELF process, ELF `offset` in ELF file equal to `vaddr`.


### PIE (hello-pie)

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
offset   = 0x0000000011e8 (st_value)
off      = 0x000000001000
vm_pgoff =              1
vaddr    = 0x56399fbf51e8
```

Calculate with `offset_to_vaddr()`

```
$ printf '0x%lx\n' $((0x000056399fbf5000 + 0x00000000000011e8 - $((1 << 12))))
0x56399fbf51e8
```

It's accurate.

And the variable `global_i` addresses be like:

```bash
vm_start = 0x56399fbf8000
offset   = 0x000000004040 (st_value)
off      = 0x000000003000
vm_pgoff =              3
vaddr    = 0x56399fbf8040
```

I guess:

```
vaddr = vm_start + offset - (off + (p_vaddr - p_offset))
```


### PIE (bash)

In ELF file:

```
$ readelf -l /bin/bash
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000021428 0x0000000000021428  R      0x1000
  LOAD           0x0000000000022000 0x0000000000022000 0x0000000000022000
                 0x00000000000ee301 0x00000000000ee301  R E    0x1000
  LOAD           0x0000000000111000 0x0000000000111000 0x0000000000111000
                 0x00000000000346a4 0x00000000000346a4  R      0x1000
  LOAD           0x0000000000145a30 0x0000000000146a30 0x0000000000146a30
                 0x000000000000bda0 0x0000000000016da8  RW     0x1000

$ readelf --syms /bin/bash | grep -e readline -e ps1_prompt -w
   937: 00000000000d1c70   201 FUNC    GLOBAL DEFAULT   17 readline
  1020: 0000000000153148     8 OBJECT  GLOBAL DEFAULT   28 ps1_prompt
```

VMAs:

```
$ cat /proc/$$/maps
5635990bd000-5635990df000 r--p 00000000 103:03 4212 /usr/bin/bash
5635990df000-5635991ce000 r-xp 00022000 103:03 4212 /usr/bin/bash
5635991ce000-563599203000 r--p 00111000 103:03 4212 /usr/bin/bash
563599203000-563599207000 r--p 00145000 103:03 4212 /usr/bin/bash
563599207000-563599210000 rw-p 00149000 103:03 4212 /usr/bin/bash
```

Address in memory:

```
$ gdb -q -p $$
(gdb) p readline
$1 = {<text variable, no debug info>} 0x56359918ec70 <readline>
(gdb) p &ps1_prompt
$2 = (<data variable, no debug info> *) 0x563599210148 <ps1_prompt>
```

And the variable `ps1_prompt` addresses be like:

```bash
vm_start = 0x563599207000
offset   = 0x000000153148 (st_value)
off      = 0x000000149000
vm_pgoff = 0x000000000149
vaddr    = 0x563599210148
```

```
vaddr = vm_start + offset - (off + (p_vaddr - p_offset))
$ printf '0x%lx\n' $(( 0x563599207000 + 0x000000153148 - (0x000000149000 + (0x0000000000146a30 - 0x0000000000145a30)) ))
0x563599210148
```

We could see the result `vaddr=0x563599210148` is correct.


## Process's VMAs

In `/proc/PID/maps`, we could see the process's VMAs, kernel will load `PT_LOAD` into memory, and `linker`(for example `/lib64/ld-linux-x86-64.so.2` on `x86_64` fedora40) will seperate some vma. for example:

non-PIE hello's `PT_LOAD`

```
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

we just start the `hello` with gdb, and `break` on linker's `_dl_start()`:

```
$ gdb ./hello
(gdb) b _dl_start
(gdb) r
Breakpoint 1, _dl_start (arg=0x7fffffffd830) at rtld.c:517
517	{
```

Then, check VMAs:

```
$ cat /proc/$(pidof hello)/maps
00400000-00401000 r--p 00000000 08:10 3115204 /ulpatch/tests/hello/hello
00401000-00402000 r-xp 00001000 08:10 3115204 /ulpatch/tests/hello/hello
00402000-00403000 r--p 00002000 08:10 3115204 /ulpatch/tests/hello/hello
00403000-00405000 rw-p 00002000 08:10 3115204 /ulpatch/tests/hello/hello
```

Then, `continue` run process:

```
(gdb) continue
```

Check VMAs again:

```
$ cat /proc/$(pidof hello)/maps
00400000-00401000 r--p 00000000 08:10 3115204 /ulpatch/tests/hello/hello
00401000-00402000 r-xp 00001000 08:10 3115204 /ulpatch/tests/hello/hello
00402000-00403000 r--p 00002000 08:10 3115204 /ulpatch/tests/hello/hello
00403000-00404000 r--p 00002000 08:10 3115204 /ulpatch/tests/hello/hello
00404000-00405000 rw-p 00003000 08:10 3115204 /ulpatch/tests/hello/hello
```

Why linker split vma `00403000-00405000 rw-p 00002000` to two different vmas `00403000-00404000 r--p 00002000` and `00404000-00405000 rw-p 00003000`? Let's see the linker's call stack in [glibc](https://sourceware.org/git/glibc) source code(my version `glibc-2.40.9000-13-g22958014ab`).

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

Let's see the PIE program.

```
555555554000-555555555000 r--p 00000000 08:10 3115207 /ulpatch/tests/hello/hello-pie
555555555000-555555556000 r-xp 00001000 08:10 3115207 /ulpatch/tests/hello/hello-pie
555555556000-555555557000 r--p 00002000 08:10 3115207 /ulpatch/tests/hello/hello-pie
555555557000-555555559000 rw-p 00002000 08:10 3115207 /ulpatch/tests/hello/hello-pie
```

Tracing `mprotect(2)`:

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

We should know why linker modify `addr=0x555555557000,len=0x4096` memory to readonly.

As we can see in `readelf -l /bin/bash` output, the `.data.rel.ro` in the last `PT_LOAD` program header and `PT_GNU_RELRO` program header, kernel will load all `PT_LOAD` into memory, then, GNU Linker will set the `.data.rel.ro` to readonly permission by `mprotect(2)` syscall, see the linker pseudocode show above. Thus, the vma `555555557000-555555559000 rw-p 00002000` will splited to two different vma `555555557000-555555558000 r--p 00002000` and `555555558000-555555559000 rw-p 00003000`.


## Share library

TODO


## Links

- https://reverseengineering.stackexchange.com/questions/16036/how-can-i-view-the-dynamic-symbol-table-of-a-running-process
- https://jvns.ca/blog/2018/01/09/resolving-symbol-addresses/
- [How gdb loads symbol files](https://sourceware.org/gdb/wiki/How%20gdb%20loads%20symbol%20files)
- GitHub: [bpftrace](https://github.com/bpftrace/bpftrace)
