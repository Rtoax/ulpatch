---
hide:
  - navigation
---

## From Source Code

### Install Dependences

#### Fedora/RHEL/AlmaLinux

On **RHEL** like linux distrobution, manage packages with [rpm](https://github.com/rpm-software-management) and [dnf/yum](https://github.com/rpm-software-management/dnf).

```bash
# Some distributions like RHEL need epel-release package, Fedora don't.
$ sudo dnf install -y epel-release
$ sudo dnf group install -y "Development Tools"
$ sudo dnf install -y \
	binutils-devel \
	capstone-devel \
	cmake \
	elfutils-devel \
	elfutils-libelf-devel \
	gcc \
	gcc-c++ \
	glibc-devel \
	libunwind-devel
```


#### Debian/Ubuntu

On **Debian** like linux distrobutions, manage packages with [dpkg](https://git.dpkg.org/git/dpkg/dpkg.git) and [apt](https://salsa.debian.org/apt-team/apt).

```bash
$ sudo apt install -y build-essential
$ sudo apt install -y \
	cmake \
	gcc \
	binutils-dev \
	libc6 \
	libcapstone-dev \
	libelf-dev \
	libunwind-dev
```

If you want to compile the website, install

```
$ sudo apt install -y mkdocs
```

Then, you could run `mkdocs build` on git-root directory, after that, running `mkdocs serve` to access local website [http://127.0.0.1:8000/ulpatch/](http://127.0.0.1:8000/ulpatch/).


### Compile

```bash
$ git clone https://github.com/rtoax/ulpatch
$ cd ulpatch
$ mkdir build
$ cd build
$ cmake -DCMAKE_INSTALL_PREFIX=/usr \
	-DCONFIG_BUILD_TESTING=OFF \
	-DCONFIG_BUILD_ULFTRACE=OFF \
	-DCONFIG_BUILD_ULTASK=OFF \
	..
$ make -j$(nproc)
```

Or you could specify `-B build` argument of cmake, like `cmake -B build -DCMAKE_BUILD_TYPE=Release`. If you want to see the compile detail, use `make VERBOSE=1`.


### CMake Macros

#### CMAKE_BUILD_TYPE

You can specify CMake Build type with `CMAKE_BUILD_TYPE`, such as `-DCMAKE_BUILD_TYPE=Debug`(`Release`,`Debug`,`RelWithDebInfo`,`MinSizeRel`), such as:

```
$ cmake -DCMAKE_BUILD_TYPE=Debug ..
```

Default is `Debug`.


#### CONFIG_BUILD_PIE_EXE

Build all executions as PIE(`Position-Independent-Executable`), such as:

```
$ cmake -DCONFIG_BUILD_PIE_EXE=1 ..
```

This cmake option is helpful if you want to test the PIE elf.


#### CONFIG_BUILD_TESTING

You can specify `CONFIG_BUILD_TESTING` to determine compile `ulpatch_test` or not, default `ON`. If you want to turn it off, such as:

```
$ cmake -DCONFIG_BUILD_TESTING=0 ..
```

#### CONFIG_BUILD_ULFTRACE

You can specify `CONFIG_BUILD_ULFTRACE` to determine compile `ulftrace` or not, default `ON`. If you want to turn it off, such as:

```
$ cmake -DCONFIG_BUILD_ULFTRACE=0 ..
```

#### CONFIG_BUILD_ULTASK

You can specify `CONFIG_BUILD_ULTASK` to determine compile `ultask` or not, default `ON`. If you want to turn it off, such as:

```
$ cmake -DCONFIG_BUILD_ULTASK=0 ..
```

#### CONFIG_BUILD_MAN

You can specify `CONFIG_BUILD_MAN` to determine compile manual pages of ULPatch or not, default `ON`. If you want to turn it off, such as:

```
$ cmake -DCONFIG_BUILD_MAN=0 ..
```

#### CONFIG_BUILD_BASH_COMPLETIONS

You can specify `CONFIG_BUILD_BASH_COMPLETIONS` to determine install bash completions of ULPatch or not, default `ON`. If you want to turn it off, such as:

```
$ cmake -DCONFIG_BUILD_BASH_COMPLETIONS=0 ..
```

#### CONFIG_CAPSTONE

CMake `CONFIG_CAPSTONE` determine compile with capstone or not, default `ON`. If you want to turn it off, such as:

```
$ cmake -DCONFIG_CAPSTONE=OFF ..
```

#### CONFIG_LIBUNWIND

CMake `CONFIG_LIBUNWIND` determine compile with libunwind or not, default `ON`. If you want to turn it off, such as:

```
$ cmake -DCONFIG_CAPSTONE=OFF ..
```

If `CONFIG_LIBUNWIND=ON(default)`, and your system donesn's have it, `cmake` will run fatal and tell you.


### Install

```bash
$ sudo make install
```

### Uninstall

```bash
$ sudo make uninstall
```


## From RPM Package

### Download

Download rpm packages from [Release page](https://github.com/Rtoax/ulpatch/releases).

### Install

Then, use `rpm` or `dnf` command to install the rpm packages.

```
$ sudo dnf install ulpatch-*.rpm
```

> Use 'localinstall' is better(dnf <= 4, dnf5 not support 'localinstall' anymore).

Or

```
$ sudo rpm -ivh ulpatch-*.rpm
```

If upgrade:

```
$ sudo rpm -iUh ulpatch-*.rpm
```

### Build RPM Packages Your Own

> Only support rpm management software system, such as Fedora, RHEL and its derivatives.

You need to install the rpm-build depends package.

```
$ sudo dnf install rpm-build
```

Then, install the depends of ulpatch according to spec:

```
$ sudo dnf builddep ulpatch.spec
```

Now, you can compile with rpmbuild. In the root directory of this project, I have written an rpmbuild(`rpmbuild.sh`) example for you. And of course, you need to archive the source code to tar package.

Generate tar archive:

```bash
$ ./archive.sh
```

Build the RPM packages:

```bash
$ ./rpmbuild.sh
```

