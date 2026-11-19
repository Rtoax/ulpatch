# AGENTS.md

This file provides context for AI agents when working on the ULPatch codebase.

## Project overview

ULPatch is open source user space live patch tool.

`rtoax/ulpatch` (ULPatch) is an open-source **userspace live patching tool** written in C, licensed under **GPL-2.0-or-later**. Its core purpose is to fix bugs or CVEs in a running process **without restarting it**.

## ULPatch Documentation

See https://rtoax.github.io/ulpatch or https://rtoax.github.io/ulpatch/zh/

### 🎯 The Problem It Solves

For long-running processes like **QEMU**, a restart is often unacceptable—it disrupts services and complicates high-availability setups. Traditional patching requires stopping the service, applying updates, and restarting, which is not always feasible. ULPatch targets exactly this gap: it allows patches to be applied to a live process in memory, keeping it running throughout the fix. The project explicitly frames itself as the userspace counterpart to the kernel's more mature `livepatch` mechanism.

### ⚙️ How It Works (Core Workflow)

The theoretical model is documented in the project's `THEORY.md`. The patching process follows four key steps:

1. **Compile a relocatable ELF**: The patch source code is compiled into a **relocatable ELF object**—this becomes the livepatch payload.
2. **Inject into the target process**: This ELF is loaded directly into the **address space** of the running target process.
3. **Perform symbol relocation**: Based on the target process's symbol table, the symbols referenced in the patch are **relocated**, so the patched code can correctly call existing functions and access data in the host process.
4. **Redirect execution**: The entry instruction of the original function is overwritten with a **jump instruction** that transfers control to the newly injected patch function. The `unpatch` operation reverses this process.

> **Note**: The current theoretical model describes a single-threaded design, but multi-threaded target processes still require consideration. This is listed as an ongoing TODO item (using `ptrace(2)` for per-thread safety).
