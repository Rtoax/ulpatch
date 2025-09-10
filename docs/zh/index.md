---
hide:
  - navigation
---

<div align="center" markdown>

# ULPatch Main Page

<center>
	<a href="images/logo.drawio.svg">
		<img src="images/logo.drawio.svg" border=0 width=300>
	</a>
</center>

</div>

## ULPatch 描述

[ULPatch](https://github.com/Rtoax/ulpatch) 是开源的用户空间热补丁工具，采用 [GPL-2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html) 或 [更高版本](https://www.gnu.org/licenses/gpl-3.0.html) 许可证。


### ULPatch Logo

我使用 [drawio](https://github.com/jgraph/drawio-desktop/releases) 绘制了上面所示的 ULPatch LOGO。这个标志的含义很明显，企鹅的意思是 ULPatch 支持 Linux，它看起来与 [Linux Tux](https://www.techrepublic.com/article/tux-a-brief-history-of-the-linux-mascot/) 不同。同时，你可以看到企鹅是由补丁组成的，而且他还活着。

> Tux，Linux 内核的官方品牌吉祥物，作者 Larry Ewing (lewing@isc.tamu.edu) 和 The GIMP。

企鹅的心脏是 CPU 图标，这表示 ULPatch 与指令集密切相关。这个 CPU 图标不是由补丁组成的，表示 ULPatch 只能应用到用户空间，毕竟内核空间有更完整的 [livepatch 机制](https://docs.kernel.org/livepatch/livepatch.html)。


## 背景

对于像 Qemu 这样无法中断和重启的进程，漏洞修复非常困难。特别是对于云供应商来说，热补丁非常重要。

当然，ULPatch 项目只讨论用户模式程序。


## ULPatch 支持的架构

由于我的知识体系和个人经验，不能理解掌握所有CPU架构，所有我只列举了我熟悉的架构，如果不能满足你的需求，环境加入我一起开发。

- [ ] `x86_64`: 快好了，支持一些小Demo.
- [ ] `aarch64`: 快好了，支持一些小Demo.
- [ ] `loongarch64`: 还不支持
- [ ] `riscv64`: 还不支持


## 相关项目

ULPatch 借鉴了 [cloudlinux/libcare](https://github.com/cloudlinux/libcare) 和华为的二次开发 [openeuler/libcareplus](https://gitee.com/openeuler/libcareplus) 等多个优秀的开源项目。SUSE 还开源了自己的实时补丁解决方案 [SUSE/libpulp](https://github.com/SUSE/libpulp)。

内核中的热补丁已经是一项比较成熟的技术。在[linux 内核](https://github.com/torvalds/linux) 中基于 ftrace 实现 [livepatch](https://docs.kernel.org/livepatch/livepatch.html)。

还有一些企业级软件。[QEMUCare](https://tuxcare.com/enterprise-live-patching-services/qemucare/) 可以在基于 QEMU 的虚拟化系统运行时自动修补它们，而无需关闭或迁移虚拟化层或重新启动。[KernelCare](https://docs.tuxcare.com/live-patching-services/) SimplePatch 是一种内核实时修补产品，可为一系列流行的 Linux 内核提供安全补丁，无需重新启动系统即可安装这些内核。

同时，内核的 `finit_module(2)` 和 `init_module(2)` 系统调用的实现也具有很大的参考价值。在 ULPatch 开发的早期阶段，重定位代码也是从这两个系统调用移植而来的。

从目前对优秀项目的研究来看，热补丁功能依赖于修改函数入口处的汇编指令，使其跳转到新的函数。

我认为我应该在另一个文档而不是 README 文件中详细说明 ULPatch 从这些开源项目中获得的灵感。


## 作者独白

**我不希望卷入许可证之战**，所以，如果本项目错误地引用了开源代码，请原谅我。毕竟，这不是一个商业项目。

我使用 [drawio](https://github.com/jgraph/drawio-desktop/releases) 绘制了 ULPatch 中显示的所有 logo 和矢量图。

我是 Linux 新手，小学生。


## 链接

- [GitHub RToax ULPatch](https://github.com/Rtoax/ulpatch)
	- [GitHub ULPatch](https://github.com/ulpatch)
- [ULPatch 文档](https://rtoax.github.io/ulpatch/zh) / [en](https://rtoax.github.io/ulpatch/)
- [Gitee ULPatch (镜像)](https://gitee.com/rtoax/ulpatch)
