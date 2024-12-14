
## Executable and Linkable Format

[ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) 是可执行文件、目标代码、共享库和核心转储的通用标准文件格式。它首先发布在名为 System V Release 4 （[SVR4](https://www.sco.com/developers/devspecs/gabi41.pdf)） 的 Unix 操作系统版本的应用程序二进制接口 （ABI） 规范中，后来又在 [工具接口标准](https://refspecs.linuxbase.org/elf/elf.pdf) 中发布，很快就被 Unix 系统的不同供应商所接受。1999 年，它被 86open 项目选为 x86 处理器上 Unix 和类 Unix 系统的标准二进制文件格式。

根据设计，[ELF 格式](https://refspecs.linuxbase.org/elf/elf.pdf) 是灵活的、可扩展的和跨平台的。例如，它支持不同的字节序和地址大小，因此不排除任何特定的 CPU 或指令集架构。这使得它能够被许多不同硬件平台上的许多不同操作系统采用。

![ELF Layout](images/Elf-layout--en.svg.png)


## ULPatch ELF 格式

TODO
