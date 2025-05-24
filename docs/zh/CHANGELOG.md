# Changelog

该项目的所有显著变化都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
并且该项目遵循
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**别忘了同步修改英文版CHNAGELOG.md文件。**


## 未发布
#### 重大变更
- 添加 `ULPATCH_LICENSE()` 并且 `ULPATCH_FILE_VERSION=5`.
#### 添加
- 添加 ulpconfig.mk。
- 添加 scripts/verbose.mk。
- 添加 docker/build.sh。
- 准备将 tests/hello 使用 cmake 编译。
- 将 git 作为依赖。
#### 更改
- task: 从core.c分离出对应特性的源码。
- tests: 重命名 tests/disasm/disasm-tst1.c 为 tests/bfd/symbol.c。
- tests: 引入linker scripts 来遍历所有测试例。
- tests: 使用linker scripts 替代 `TEST_STUB()`。
#### 弃用
#### 移除
- 移除 tests/disasm/disasm-tst0.c。
#### 修复
- 修复tests/disasm编译问题。
- 传递`task_attach()` 的返回值到调用者。
#### 安全
#### 文档
#### 工具
#### 测试
- 仅仅在编译ultask和ulftrace时才测试它们。
- 添加 tests/bfd 到 CMake 编译列表。


## v0.5.13

#### 重大变更
- 添加`ULPATCH_AUTHOR()`并且修改`ULPATCH_FILE_VERSION=4`。
#### 添加
- 添加scripts/modify-return.sh修改函数返回值为false。
- 添加CMake宏 `CONFIG_OPENSSL`。
- 增加对 OpenSSL 的依赖，并且添加 fmd5sum() 相关函数。
- 增加头文件 /usr/include/ulpatch/version.h。
- rpmbuild.sh 添加 --nocheck 参数。
- task: 添加C宏 `task_vdso_vma(task)`。
- ultask: 支持 `--dump vdso`。
#### 更改
- 重命名 src/ulconfig 为 src/ulpconfig.sh.in。
#### 弃用
#### 移除
#### 修复
#### 安全
#### 文档
- 添加 CHANGELOG.md
- man手册添加Copyright注释。
#### 工具
