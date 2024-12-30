#!/bin/bash
set -ex

cat /etc/os-release
systemd-detect-virt || true
uname -a
# Fedora base container doesn't contain ip command.
ip addr || true
