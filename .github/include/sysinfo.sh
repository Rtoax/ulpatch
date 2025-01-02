#!/bin/bash
set -ex

cat /etc/os-release
systemd-detect-virt || true
uname -a
free -g
nproc
lscpu
# Fedora base container doesn't contain ip command.
ip addr || true
gcc --version
ldconfig --version
echo cwd=$PWD
ls -al
