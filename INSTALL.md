# elftools Install

- [Building elftools](#building-elftools)
	- [CentOS](#centos)

# Building elftools

## CentOS

### CentOS Stream 9

```bash
sudo dnf up -y
sudo dnf install -y \
	glibc-headers \
	cmake \
	gcc \
	elfutils-libelf-devel \
	json-c-devel \
	linenoise-devel \
	systemtap-sdt-devel \
	libunwind-devel
cd elftools
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make -j$(nproc)
sudo make install
```

