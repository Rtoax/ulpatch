How to Compile?
===============

```bash
$ mkdir build
$ cd build
$ cmake -DBUILD_TESTING=OFF -DBUILD_ULFTRACE=OFF -DBUILD_ULTASK=OFF ..
$ make -j$(npro)
```
