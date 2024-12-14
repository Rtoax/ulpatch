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

## ULPatch Description

[ULPatch](https://github.com/Rtoax/ulpatch) is open source user space live patch tool, under [GPL-2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html) or [later](https://www.gnu.org/licenses/gpl-3.0.html) license.


### ULPatch Logo

I drew the ULPatch logo shown above using [drawio](https://github.com/jgraph/drawio-desktop/releases). The meaning of this logo is obvious, the penguin means that ULPatch supports Linux, and he looks different from [Linux Tux](https://www.techrepublic.com/article/tux-a-brief-history-of-the-linux-mascot/). And at the same time, you can see that the penguin is made up of patches and that he is alive.

> Tux, the official brand character of the Linux Kernel; by Larry Ewing (lewing@isc.tamu.edu) and The GIMP.

The heart of a penguin is a CPU, which of course is closely related to the instruction set. This CPU icon is not made up of patches, I mean, ULPatch can only be applied to the user space, after all, the kernel space has a more complete [livepatch mechanism](https://docs.kernel.org/livepatch/livepatch.html).


## Background

For a process like Qemu that cannot be interrupted and restarted, vulnerability fixing is very difficult. Especially for cloud vendors, the live patch is very important.

Of course, the ULPatch project only discusses user-mode programs.


## Related Projects

ULPatch draws on several excellent open source projects, such as [cloudlinux/libcare](https://github.com/cloudlinux/libcare), and Huawei’s secondary development [openeuler/libcareplus](https://gitee.com/openeuler/libcareplus). SUSE has also open sourced its own live patch solution [SUSE/libpulp](https://github.com/SUSE/libpulp).

Hot patching in the kernel is already a relatively mature technology. Implementing [livepatch](https://docs.kernel.org/livepatch/livepatch.html) based on ftrace in the [linux kernel](https://github.com/torvalds/linux).

There are also some enterprise-level software. [QEMUCare](https://tuxcare.com/enterprise-live-patching-services/qemucare/) can automatically patch your QEMU-based virtualization systems while they're running, without needing to shut down or migrate the virtualization layer or reboot. [KernelCare](https://docs.tuxcare.com/live-patching-services/) SimplePatch is a kernel live patching product that provides security patches for a range of popular Linux kernels that can be installed without rebooting the system.

At the same time, the implementation of the kernel's `finit_module(2)` and `init_module(2)` system calls is also of great reference value. Even in the early stages of ULPatch development, the relocation code was transplanted from these two system calls.

Judging from the current research on outstanding projects, the live patch function relies on modifying the assembly instructions at the function entrance to make it jump to a new function.

I think I should detail the inspiration of ULPatch from these open source projects in another document instead of a README file.


## Author's Monologue

**I don't want to get involved in the License wars**, so please forgive me if the project misquote open source code. After all, this is not a commercial project.

My native language is Chinese, not English, so please excuse my poor English grammar.

I drew all logo/svg shown in ULPatch using [drawio](https://github.com/jgraph/drawio-desktop/releases).

I'm a Linux Newbie, little student.


## Links

- [GitHub ULPatch](https://github.com/Rtoax/ulpatch)
- [ULPatch Documents](https://rtoax.github.io/ulpatch/) / [zh](https://rtoax.github.io/ulpatch/zh/)
- [Gitee ULPatch (mirror)](https://gitee.com/rtoax/ulpatch)

