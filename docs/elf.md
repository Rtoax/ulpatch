

## ELF Header

```
$ readelf -h hello
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x4010f0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          18064 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         39
  Section header string table index: 38
```


## Program Headers

```
$ readelf -l hello

Elf file type is EXEC (Executable file)
Entry point 0x4010f0
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000400040 0x0000000000400040
                 0x00000000000002d8 0x00000000000002d8  R      0x8
  INTERP         0x0000000000000318 0x0000000000400318 0x0000000000400318
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x0000000000000650 0x0000000000000650  R      0x1000
  LOAD           0x0000000000001000 0x0000000000401000 0x0000000000401000
                 0x0000000000000379 0x0000000000000379  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000402000 0x0000000000402000
                 0x00000000000001d4 0x00000000000001d4  R      0x1000
  LOAD           0x0000000000002df8 0x0000000000403df8 0x0000000000403df8
                 0x0000000000000248 0x0000000000000260  RW     0x1000
  DYNAMIC        0x0000000000002e08 0x0000000000403e08 0x0000000000403e08
                 0x00000000000001d0 0x00000000000001d0  RW     0x8
  NOTE           0x0000000000000338 0x0000000000400338 0x0000000000400338
                 0x0000000000000050 0x0000000000000050  R      0x8
  NOTE           0x0000000000000388 0x0000000000400388 0x0000000000400388
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_PROPERTY   0x0000000000000338 0x0000000000400338 0x0000000000400338
                 0x0000000000000050 0x0000000000000050  R      0x8
  GNU_EH_FRAME   0x0000000000002058 0x0000000000402058 0x0000000000402058
                 0x0000000000000054 0x0000000000000054  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000002df8 0x0000000000403df8 0x0000000000403df8
                 0x0000000000000208 0x0000000000000208  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt
   03     .init .plt .plt.sec .text .fini
   04     .rodata .eh_frame_hdr .eh_frame
   05     .init_array .fini_array .dynamic .got .got.plt .data .bss
   06     .dynamic
   07     .note.gnu.property
   08     .note.gnu.build-id .note.ABI-tag
   09     .note.gnu.property
   10     .eh_frame_hdr
   11
   12     .init_array .fini_array .dynamic .got
```

## Section Headers

```
$ readelf -S hello
There are 39 section headers, starting at offset 0x4690:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400318  00000318
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.gnu.pr[...] NOTE             0000000000400338  00000338
       0000000000000050  0000000000000000   A       0     0     8
  [ 3] .note.gnu.bu[...] NOTE             0000000000400388  00000388
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .note.ABI-tag     NOTE             00000000004003ac  000003ac
       0000000000000020  0000000000000000   A       0     0     4
  [ 5] .gnu.hash         GNU_HASH         00000000004003d0  000003d0
       0000000000000024  0000000000000000   A       6     0     8
  [ 6] .dynsym           DYNSYM           00000000004003f8  000003f8
       00000000000000d8  0000000000000018   A       7     1     8
  [ 7] .dynstr           STRTAB           00000000004004d0  000004d0
       0000000000000078  0000000000000000   A       0     0     1
  [ 8] .gnu.version      VERSYM           0000000000400548  00000548
       0000000000000012  0000000000000002   A       6     0     2
  [ 9] .gnu.version_r    VERNEED          0000000000400560  00000560
       0000000000000030  0000000000000000   A       7     1     8
  [10] .rela.dyn         RELA             0000000000400590  00000590
       0000000000000030  0000000000000018   A       6     0     8
  [11] .rela.plt         RELA             00000000004005c0  000005c0
       0000000000000090  0000000000000018  AI       6    24     8
  [12] .init             PROGBITS         0000000000401000  00001000
       000000000000001b  0000000000000000  AX       0     0     4
  [13] .plt              PROGBITS         0000000000401020  00001020
       0000000000000070  0000000000000010  AX       0     0     16
  [14] .plt.sec          PROGBITS         0000000000401090  00001090
       0000000000000060  0000000000000010  AX       0     0     16
  [15] .text             PROGBITS         00000000004010f0  000010f0
       000000000000027b  0000000000000000  AX       0     0     16
  [16] .fini             PROGBITS         000000000040136c  0000136c
       000000000000000d  0000000000000000  AX       0     0     4
  [17] .rodata           PROGBITS         0000000000402000  00002000
       0000000000000056  0000000000000000   A       0     0     8
  [18] .eh_frame_hdr     PROGBITS         0000000000402058  00002058
       0000000000000054  0000000000000000   A       0     0     4
  [19] .eh_frame         PROGBITS         00000000004020b0  000020b0
       0000000000000124  0000000000000000   A       0     0     8
  [20] .init_array       INIT_ARRAY       0000000000403df8  00002df8
       0000000000000008  0000000000000008  WA       0     0     8
  [21] .fini_array       FINI_ARRAY       0000000000403e00  00002e00
       0000000000000008  0000000000000008  WA       0     0     8
  [22] .dynamic          DYNAMIC          0000000000403e08  00002e08
       00000000000001d0  0000000000000010  WA       7     0     8
  [23] .got              PROGBITS         0000000000403fd8  00002fd8
       0000000000000010  0000000000000008  WA       0     0     8
  [24] .got.plt          PROGBITS         0000000000403fe8  00002fe8
       0000000000000048  0000000000000008  WA       0     0     8
  [25] .data             PROGBITS         0000000000404030  00003030
       0000000000000010  0000000000000000  WA       0     0     4
  [26] .bss              NOBITS           0000000000404040  00003040
       0000000000000018  0000000000000000  WA       0     0     8
  [27] .comment          PROGBITS         0000000000000000  00003040
       000000000000005c  0000000000000001  MS       0     0     1
  [28] .annobin.notes    STRTAB           0000000000000000  0000309c
       000000000000014f  0000000000000001  MS       0     0     1
  [29] .gnu.build.a[...] NOTE             0000000000406058  000031ec
       0000000000000144  0000000000000000           0     0     4
  [30] .debug_aranges    PROGBITS         0000000000000000  00003330
       0000000000000030  0000000000000000           0     0     1
  [31] .debug_info       PROGBITS         0000000000000000  00003360
       000000000000040f  0000000000000000           0     0     1
  [32] .debug_abbrev     PROGBITS         0000000000000000  0000376f
       00000000000001a9  0000000000000000           0     0     1
  [33] .debug_line       PROGBITS         0000000000000000  00003918
       0000000000000126  0000000000000000           0     0     1
  [34] .debug_str        PROGBITS         0000000000000000  00003a3e
       00000000000002f7  0000000000000001  MS       0     0     1
  [35] .debug_line_str   PROGBITS         0000000000000000  00003d35
       00000000000000b4  0000000000000001  MS       0     0     1
  [36] .symtab           SYMTAB           0000000000000000  00003df0
       0000000000000498  0000000000000018          37    27     8
  [37] .strtab           STRTAB           0000000000000000  00004288
       0000000000000274  0000000000000000           0     0     1
  [38] .shstrtab         STRTAB           0000000000000000  000044fc
       0000000000000194  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
```

## Relationship Between shdr and phdr

```
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000001000 0x0000000000401000 0x0000000000401000
                 0x0000000000000379 0x0000000000000379  R E    0x1000
   03     .init .plt .plt.sec .text .fini

  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [15] .text             PROGBITS         00000000004010f0  000010f0
       000000000000027b  0000000000000000  AX       0     0     16
```

The section `.text` range `Offset ~ Offset + Size` is in `Offset ~ Offset + FileSiz`.

