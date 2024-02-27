ULPatch Install
===============

# Install Dependences

## Fedora/RHEL/ALmaLinux

```bash
$ sudo dnf install -y glibc-devel cmake gcc binutils-devel elfutils-libelf-devel libunwind-devel
```

## Debian/Ubuntu

```bash
$ sudo apt install -y libc6 cmake gcc binutils-dev libunwind-dev
```

# Compile

```bash
$ cd ulpatch
$ mkdir build
$ cd build
$ cmake -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_TESTING=OFF -DBUILD_ULFTRACE=OFF -DBUILD_ULTASK=OFF ..
$ make -j$(nproc)
```

You can specify CMake Build type with `CMAKE_BUILD_TYPE`, such as `-DCMAKE_BUILD_TYPE=Debug`(`Release`,`Debug`,`RelWithDebInfo`,`MinSizeRel`), such as:

```
$ cmake -DCMAKE_BUILD_TYPE=Debug ..
```


# Install

```bash
$ sudo make install
```

# Uninstall

```bash
$ sudo make uninstall
```
