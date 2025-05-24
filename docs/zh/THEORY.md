---
hide:
  - navigation
---

## 原理

本页只介绍了 ULPatch 的原理，没有介绍具体实现细节。

所有程序都是单线程模型，因此您不会在代码中看到同步锁。当然，我们需要考虑目标进程的多线程情况。


## ULPatch

### Patch

下图显示了 Livepatch 加载过程。

![ulpatch::patch](images/ulpatch-patch.drawio.svg){: style="display: block; margin: 0 auto; width: 50%;"}

具体步骤如下：

1. 将源代码编译成一个可重定位的 ELF 文件，即 livepatch 文件;
2. 将可重定位的 ELF 文件加载到目标进程地址空间;
3. 根据目标进程地址符号表，对 patch 中的符号进行重新定位;
4. 修改 patch 函数入口，跳转到 patch 函数;

目标函数的起始指令将被替换为跳转至补丁函数的跳转指令，如下图所示：

![ulpatch::callee](images/ulpatch-func-trampoline.drawio.svg){: style="display: block; margin: 0 auto; width: 60%;"}


### Unpatch

Livepatch 的卸载过程如下图所示。

![ulpatch::unpatch](images/ulpatch-unpatch.drawio.svg){: style="display: block; margin: 0 auto; width: 40%;"}

`unpatch` 操作是 `patch` 的反向操作，但没有重定位过程。


## ULTask

ULTask 是修改目标进程的有用工具，我称之为 **Program Modifier**。`CONFIG_BUILD_ULTASK` 决定是否编译 `ultask`。查看手册 `ultask(8)` 以了解更多信息。

ULTask 使用 `/proc/` 文件系统对对目标进程进行修改和查看。例如，通过 `/proc/PID/mem` 对目标进程内存进行读取或修改。

TODO


## ULFtrace

与 [linux ftrace](https://www.kernel.org/doc/html/latest/trace/ftrace.html) 相同，需要 gcc `-pg` 编译选项。`CONFIG_BUILD_ULFTRACE` 决定是否编译 `ulftrace`。查看手册 `ulftrace(8)` 以了解更多信息。

TODO
