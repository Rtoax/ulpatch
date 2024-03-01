
## Relocations

Relocation is the process of connecting symbolic references with symbolic definitions. For example, when a program calls a function, the associated call instruction must transfer control to the proper destination address at execution.

Relocatable files must have `relocation entries` which are necessary because they contain information that describes how to modify their section contents, thus allowing executable and shared object files to hold the right information for a process's program image.

```c
typedef struct {
	Elf32_Addr	r_offset;
	Elf32_Word	r_info;
} Elf32_Rel;

typedef struct {
	Elf32_Addr	r_offset;
	Elf32_Word	r_info;
	Elf32_Sword	r_addend;
} Elf32_Rela;

typedef struct {
	Elf64_Addr	r_offset;
	Elf64_Xword	r_info;
} Elf64_Rel;

typedef struct {
	Elf64_Addr	r_offset;
	Elf64_Xword	r_info;
	Elf64_Sxword	r_addend;
} Elf64_Rela;
```


## Dynamic Relocations

## Links

- GitHub: [Application Binary Interface for the Arm® Architecture](https://github.com/ARM-software/abi-aa/releases)
- https://refspecs.linuxbase.org/: [Relocation](https://refspecs.linuxbase.org/elf/gabi4+/ch4.reloc.html)
- [Relocations: fantastic symbols, but where to find them?](https://gotplt.org/posts/relocations-fantastic-symbols-but-where-to-find-them.html)
- PDF: [ELF for the ARM® 64-bit Architecture (AArch64)](https://docslib.org/doc/4448214/elf-for-the-arm-64-bit-architecture-aarch64)
- wikipedia: https://en.wikipedia.org/wiki/Relocation_(computing)

