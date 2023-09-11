How to Compile?
===============

```bash
$ mkdir build
$ cd build
$ cmake -DBUILD_TESTING=OFF -DBUILD_UFTRACE=OFF -DBUILD_UTASK=OFF ..
$ make -j$(npro)
```
