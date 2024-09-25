#!/bin/bash
make clean
make NO_LIBC=1 -j$(nproc)
