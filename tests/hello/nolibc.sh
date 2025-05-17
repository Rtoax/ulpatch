#!/bin/bash
set -e
make clean
make NOLIBC=1 -j$(nproc) "$@"
