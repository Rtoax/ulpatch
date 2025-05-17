# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Don't forget to modify Chinese version CHANGELOG.md at the same time.**


## Unreleased

#### Breaking Changes
- Add `ULPATCH_LICENSE()` and `ULPATCH_FILE_VERSION=5`.
#### Added
- Add git as depends.
- task: add auxv.c
#### Changed
- tests: Introduce linker scripts to iterate all tests.
- tests: Use linker scripts instead of `TEST_STUB()`.
#### Deprecated
#### Removed
#### Fixed
- Pass `task_attach()` return value to caller.
#### Security
#### Docs
#### Tools
#### Tests
- Only tests ultask and ulftrace if built.

## v0.5.13

#### Breaking Changes
- Add `ULPATCH_AUTHOR()` and `ULPATCH_FILE_VERSION=4`.
#### Added
- Add scripts/modify-return.sh to modify function return value to false.
- Add CMake macro `CONFIG_OPENSSL`
- Add OpenSSL depends and add fmd5sum() function.
- Add header file /usr/include/ulpatch/version.h.
- rpmbuild.sh add --nocheck argument.
- task: Add C macro `task_vdso_vma(task)`
- ultask: support --dump vdso.
#### Changed
- Rename src/ulconfig to src/ulpconfig.sh.in
#### Deprecated
#### Removed
#### Fixed
#### Security
#### Docs
- Add CHANGELOG.md
- Manual add copyright comment.
#### Tools
