#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
set -e

pid=( $(pidof hello hello-pie || true) )
[[ -z "${pid}" ]] && echo "ERROR: run hello or hello-pie first." && exit 1
[[ ${#pid[@]} -gt 1 ]] && echo "ERROR: too much processes are running." && exit 1

# Get libc ELF base address in memory
libc_base_addr=$( grep libc.so.6 /proc/${pid}/maps | head -n1 | tr '-' ' ' | awk '{print $1}' )

./pdlsym_tst -p ${pid} -a 0x${libc_base_addr} -s printf
