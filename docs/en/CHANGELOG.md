# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Don't forget to modify Chinese version CHANGELOG.md at the same time.**


## Unreleased

#### Breaking Changes
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
