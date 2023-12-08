ULPatch Install
===============

# Install Dependences

## rpm/dnf packages management

```bash
$ sudo dnf install -y glibc-headers cmake gcc elfutils-libelf-devel libunwind-devel
```

# Compile

```bash
$ cd ulpatch
$ mkdir build
$ cd build
$ cmake -DCMAKE_INSTALL_PREFIX=/usr ..
$ make -j$(nproc)
```

# Install

```bash
$ sudo make install
```
