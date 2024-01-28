Symbol Value
============

# LSB executable

## Example 1: on x86_64

The `PT_LOAD` in ELF file:

```
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
                 0x0000000000000240 0x0000000000000250  RW     0x1000
```

The `PT_LOAD` in `VMA` address space:

```
$ cat /proc/$(pidof hello)/maps
00400000-00401000 r--p 00000000 08:10 9547381   /home/rongtao/Git/ulpatch/tests/hello/hello
00401000-00402000 r-xp 00001000 08:10 9547381   /home/rongtao/Git/ulpatch/tests/hello/hello
00402000-00403000 r--p 00002000 08:10 9547381   /home/rongtao/Git/ulpatch/tests/hello/hello
00403000-00404000 r--p 00002000 08:10 9547381   /home/rongtao/Git/ulpatch/tests/hello/hello
00404000-00405000 rw-p 00003000 08:10 9547381   /home/rongtao/Git/ulpatch/tests/hello/hello
[...]
```

The symbol value in ELF file:

```
$ readelf --syms /home/rongtao/Git/ulpatch/tests/hello/hello
[...]
Symbol table '.symtab' contains 46 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
    [...]
    12: 0000000000404034     4 OBJECT  LOCAL  DEFAULT   24 keep_running
    13: 0000000000404040     8 OBJECT  LOCAL  DEFAULT   25 count
    14: 0000000000401176    41 FUNC    LOCAL  DEFAULT   14 sig_handler
    15: 000000000040119f    44 FUNC    LOCAL  DEFAULT   14 internal_print_hello
    16: 00000000004011cb    27 FUNC    LOCAL  DEFAULT   14 print_hello
    17: 00000000004011e6    79 FUNC    LOCAL  DEFAULT   14 routine
    [...]
    40: 0000000000401235   188 FUNC    GLOBAL DEFAULT   14 main
```

The symbol value in address space:

```
$ gdb -q -p $(pidof hello)
[...]
(gdb) p &keep_running
$3 = (sig_atomic_t *) 0x404034 <keep_running>
(gdb) p &count
$1 = (unsigned long *) 0x404040 <count>
(gdb) p sig_handler
$1 = {void (int)} 0x401176 <sig_handler>
(gdb) p internal_print_hello
$2 = {void (unsigned long)} 0x40119f <internal_print_hello>
(gdb) p print_hello
$3 = {void (unsigned long)} 0x4011cb <print_hello>
(gdb) p routine
$1 = {void *(void *)} 0x4011e6 <routine>
(gdb) p main
$2 = {int (int, char **)} 0x401235 <main>
```

And the auxiliary vector:

```
$ ultask -p $(pidof hello) --auxv
TYPE     VALUE
AT_PHDR  0x400040
AT_BASE  0x7ff11afbb000
AT_ENTRY 0x401090
```

There are two different situation. The first is the `p_vaddr != 0`, then the min address of `PT_LOAD` equal to `p_vaddr`.

For example `print_hello`:

```
maps:	0x0000000000400000
ELF:	0x00000000004011cb
GDB:	0x00000000004011cb
```


## Example 2: on aarch64

The `PT_LOAD` in ELF file:

```
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

```
$ cat /proc/$(pidof hello)/maps
5585750000-5585751000 r-xp 00000000 b3:02 1061352   /home/rongtao/Git/ulpatch/tests/hello/hello
558576f000-5585770000 r--p 0000f000 b3:02 1061352   /home/rongtao/Git/ulpatch/tests/hello/hello
5585770000-5585771000 rw-p 00010000 b3:02 1061352   /home/rongtao/Git/ulpatch/tests/hello/hello
```
The symbol value in ELF file:

```
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

```
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

```
$ ultask -p $(pidof hello) --auxv
TYPE     VALUE
AT_PHDR  0x5585750040
AT_BASE  0x7f8c1de000
AT_ENTRY 0x5585750800
```

# Share library

TODO


# Links

- https://reverseengineering.stackexchange.com/questions/16036/how-can-i-view-the-dynamic-symbol-table-of-a-running-process
