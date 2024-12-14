
## ELF 重定位

重定位是将符号引用与符号定义连接起来的过程。例如，当程序调用函数时，关联的调用指令必须在执行时将控制权转移到正确的目标地址。

可重定位文件必须具有必要的**重定位条目**，因为它们包含描述如何修改其节内容的信息，从而允许可执行和共享目标文件保存进程程序映像的正确信息。

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


## 动态重定位

TODO


## 运行进程重定位

TODO


## PIE 重定位

> PIE: Position-Independent-Executable

TODO


## 链接

- GitHub: [Application Binary Interface for the Arm® Architecture](https://github.com/ARM-software/abi-aa/releases)
	- [aarch64 ELF64](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst)
- https://refspecs.linuxbase.org/: [Relocation](https://refspecs.linuxbase.org/elf/gabi4+/ch4.reloc.html)
- [Relocations: fantastic symbols, but where to find them?](https://gotplt.org/posts/relocations-fantastic-symbols-but-where-to-find-them.html)
- PDF: [ELF for the ARM® 64-bit Architecture (AArch64)](https://docslib.org/doc/4448214/elf-for-the-arm-64-bit-architecture-aarch64)
- wikipedia: https://en.wikipedia.org/wiki/Relocation_(computing)
