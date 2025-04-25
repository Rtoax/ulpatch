---
hide:
  - navigation
---


## 未完成任务列表

### 当前任务

- 像GDB一样支持加载符号表。
- 一些符号将被优化掉，如何处理？
- 支持 Qemu。
- 支持多线程，并线程安全，使用`ptrace(2)`。
- 添加已经载入补丁的符号表，用以支持互相依赖的补丁。
- 支持未初始化的变量，见`.bss` `SHT_NOBITS`。
- ULPatch VMA 最好不使用文件映射。
- 重定位条目超出地址空间范围。
  - 可参见内核补丁集 [arm64: module: improve module VA range selection](https://lore.kernel.org/all/20230530110328.2213762-1-mark.rutland@arm.com/)


### 未来规划

- 支持动态库的热补丁。
- 支持静态编译的可执行文件。
- 支持签名和检测。
- 支持无符号表（`strip`）的可执行文件，符号表。
- 支持`loongarch64`。
- 支持 GUI，可以用 GTK/Qt 实现。
- 像内核`module_init`,`module_exit`一样支持执行初始化和退出函数。
- 或许我们应该使用 `dlopen/dlsym` 实现热补丁的插入。


### 不打算支持 (理想很丰满、现实很骨感)

- 匿名 VMA 命名，使用`prctl(2)`(`CONFIG_ANON_VMA_NAME`)设置 VMA 名字，我尝试提交了补丁，但是**David Hildenbrand**不喜欢，参见 [LKML Link](https://lore.kernel.org/lkml/b2f4c084-47dc-4e92-a9e3-daec3f48425d@redhat.com/)。
