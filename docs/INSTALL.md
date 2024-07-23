---
hide:
  - navigation
---

## From Source Code

### Install Dependences

#### Fedora/RHEL/ALmaLinux

```bash
$ sudo dnf install -y \
	binutils-devel \
	cmake \
	elfutils-devel \
	elfutils-libelf-devel \
	gcc \
	gcc-c++ \
	glibc-devel \
	libunwind-devel
```


#### Debian/Ubuntu

```bash
$ sudo apt install -y \
	binutils-dev \
	cmake \
	gcc \
	gcc-c++ \
	libc6 \
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
	-DBUILD_TESTING=OFF \
	-DBUILD_ULFTRACE=OFF \
	-DBUILD_ULTASK=OFF \
	..
$ make -j$(nproc)
```


### CMake Macros

#### CMAKE_BUILD_TYPE

You can specify CMake Build type with `CMAKE_BUILD_TYPE`, such as `-DCMAKE_BUILD_TYPE=Debug`(`Release`,`Debug`,`RelWithDebInfo`,`MinSizeRel`), such as:

```
$ cmake -DCMAKE_BUILD_TYPE=Debug ..
```

#### BUILD_TESTING

You can specify `BUILD_TESTING` to determine compile `ulpatch_test` or not, default `ON`.
If you want to turn it off, such as:

```
$ cmake -DBUILD_TESTING=0 ..
```

#### BUILD_ULFTRACE

You can specify `BUILD_ULFTRACE` to determine compile `ulftrace` or not, default `ON`.
If you want to turn it off, such as:

```
$ cmake -DBUILD_ULFTRACE=0 ..
```

#### BUILD_ULTASK

You can specify `BUILD_ULTASK` to determine compile `ultask` or not, default `ON`.
If you want to turn it off, such as:

```
$ cmake -DBUILD_ULTASK=0 ..
```

#### BUILD_MAN

You can specify `BUILD_MAN` to determine compile manual pages of ULPatch or not, default `ON`.
If you want to turn it off, such as:

```
$ cmake -DBUILD_MAN=0 ..
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

