---
hide:
  - navigation
---


## 未完成列表

### 当前任务

- 像GDB一样支持加载符号表。
- 一些符号将被优化掉，如何处理？
- 支持 Qemu。
- 支持多线程，并线程安全，使用`ptrace(2)`。
- 添加已经载入补丁的符号表，用以支持互相依赖的补丁。
- 支持未初始化的变量，见`.bss` `SHT_NOBITS`。
- ULPatch VMA 最好不使用文件映射。


### 未来规划

- 支持静态编译的可执行文件。
- 支持签名和检测。
- 支持strip的可执行文件，符号表。
- 支持`loongarch64`。
- 支持GUI，可以用GTK/Qt实现。
- 像内核`module_init`,`module_exit`一样支持执行初始化和退出函数。
- 或许我们应该使用 `dlopen/dlsym` 实现热补丁的插入。


### 不打算支持 (理想很丰满、现实很骨感)

- 匿名vma命名，使用`prctl(2)`(`CONFIG_ANON_VMA_NAME`)设置VMA名字，我尝试提交了补丁，但是**David Hildenbrand**不喜欢，参见 [LKML Link](https://lore.kernel.org/lkml/b2f4c084-47dc-4e92-a9e3-daec3f48425d@redhat.com/)。
