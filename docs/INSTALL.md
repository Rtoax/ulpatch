---
hide:
  - navigation
---

## From Source Code

### Install Dependences

#### Fedora/RHEL/AlmaLinux

On **RHEL** like linux distrobution, manage packages with [rpm](https://github.com/rpm-software-management) and [dnf/yum](https://github.com/rpm-software-management/dnf).

```bash
# RHEL like distributions need epel-release, Fedora don't.
$ sudo dnf install -y epel-release
$ sudo dnf groupinstall -y "Development Tools" "Development Libraries"
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

On **Debian** like linux distrobutions, manage packages with [apt](https://salsa.debian.org/apt-team/apt).

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

Or you could specify `-B build` argument of cmake, like `cmake -B build -DCMAKE_BUILD_TYPE=Release`.


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

You can specify `CONFIG_BUILD_TESTING` to determine compile `ulpatch_test` or not, default `ON`.
If you want to turn it off, such as:

```
$ cmake -DCONFIG_BUILD_TESTING=0 ..
```

#### CONFIG_BUILD_ULFTRACE

You can specify `CONFIG_BUILD_ULFTRACE` to determine compile `ulftrace` or not, default `ON`.
If you want to turn it off, such as:

```
$ cmake -DCONFIG_BUILD_ULFTRACE=0 ..
```

#### CONFIG_BUILD_ULTASK

You can specify `CONFIG_BUILD_ULTASK` to determine compile `ultask` or not, default `ON`.
If you want to turn it off, such as:

```
$ cmake -DCONFIG_BUILD_ULTASK=0 ..
```

#### CONFIG_BUILD_MAN

You can specify `CONFIG_BUILD_MAN` to determine compile manual pages of ULPatch or not, default `ON`.
If you want to turn it off, such as:

```
$ cmake -DCONFIG_BUILD_MAN=0 ..
```

#### BUILD_WITH_CAPSTONE

CMake `BUILD_WITH_CAPSTONE` determine compile with capstone or not, default `ON`.
If you want to turn it off, such as:

```
$ cmake -DBUILD_WITH_CAPSTONE=OFF ..
```


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

Or

```
$ sudo rpm -ivh ulpatch-*.rpm
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

