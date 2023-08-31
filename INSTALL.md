Upatch Install
===============

# Install Dependences

## CentOS Fedora RHEL

```bash
$ sudo dnf install -y glibc-headers cmake gcc elfutils-libelf-devel systemtap-sdt-devel libunwind-devel
```

# Compile

```bash
$ cd upatch
$ mkdir build
$ cd build
$ cmake -DCMAKE_INSTALL_PREFIX=/usr ..
$ make -j$(nproc)
```

# Install

```bash
$ sudo make install
```
