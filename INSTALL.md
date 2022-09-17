# upatch Install

- [Building upatch](#building-upatch)
	- [CentOS](#centos)

# Building upatch

## CentOS

### CentOS Stream 9

```bash
sudo dnf up -y
sudo dnf install -y \
	glibc-headers \
	cmake \
	gcc \
	elfutils-libelf-devel \
	systemtap-sdt-devel \
	libunwind-devel
cd upatch
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make -j$(nproc)
sudo make install
```

