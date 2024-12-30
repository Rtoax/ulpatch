## ULPatch 开发指南

本文档介绍 ULPatch 的开发指南。请在提交补丁前阅读。


### 背景

在我看来，如果你想要开发 ULPatch，需要有些预备知识：

- Linux 基础；
- ELF 格式；
- ELF 重定向；
- Linux 内核如何加载 ELF 并运行的；
- GNU linker 是如何工作的；


### 预防措施

你可以查看 ULPatch 的 [未完成工作列表](./TODO.md)，并且你需要遵守 [代码风格](./code-style.md) 和 [Contributing](./CONTRIBUTING.md) 规则。


### CMake 编译宏 Macros

参见 [ULPatch安装文档](./INSTALL.md).


### C 宏

#### current

像内核的 `current`，`current` 表示当前被打开的远端进程。


### GitHub CI

参见 [ulpatch/.github](https://github.com/Rtoax/ulpatch/tree/master/.github/workflows)。
